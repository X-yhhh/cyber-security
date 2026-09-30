package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/keystore"
	"github.com/xyh/cyber-security/sensor/internal/pipeline"
	"github.com/xyh/cyber-security/sensor/internal/spec"
	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

// Version 是传感器版本，随心跳上报。
const Version = "sensor-go/0.1.0"

// HealthInterval 是健康窗口长度。
const HealthInterval = 60 * time.Second

// Control 是心跳与健康窗口的发送端（便于测试替换）。
type Control interface {
	Heartbeat(ctx context.Context, observedAt time.Time, agentVersion string, capabilities map[string]any) error
	SubmitHealth(ctx context.Context, h uplink.HealthWindow) error
}

// Capabilities 是心跳能力声明；不含地址、接口名以外的主机信息。
func Capabilities(iface string) map[string]any {
	return map[string]any{"capture": "libpcap", "interface": iface, "snapLen": spec.SnapLen,
		"featureContractVersion": spec.ContractVersion, "addressFamilies": []string{"ipv4", "ipv6"},
		"payloadCapture": false, "firewallActions": false}
}

// LocalAddrs 读取授权接口上的本机地址与 IPv4 子网（用于视角判定与定向广播排除）。
func LocalAddrs(iface string) ([]netip.Addr, []netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("找不到接口: %w", err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}
	var local []netip.Addr
	var subnets []netip.Prefix
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		local = append(local, p.Addr().Unmap())
		if p.Addr().Unmap().Is4() {
			subnets = append(subnets, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()))
		}
	}
	if len(local) == 0 {
		return nil, nil, errors.New("授权接口上没有地址")
	}
	return local, subnets, nil
}

// LoadCredential 只从密钥库读取机器凭据。
func LoadCredential(ks keystore.Store, local LocalConfig) (uplink.Credential, error) {
	raw, err := ks.Get(local.KeystoreService, local.KeystoreAccount)
	if err != nil {
		return uplink.Credential{}, err
	}
	return uplink.ParseCredential(raw)
}

// RunLive 拉取并校验配置 → 心跳 → 实时抓包与上报，直到 ctx 取消或上报停止。
// h 是已打开的抓包句柄（可能在降权前以 root 打开）；后端批准的接口必须与之相同。
func RunLive(ctx context.Context, local LocalConfig, client *uplink.Client, bootID string, h *capture.LiveHandle) error {
	cfg, err := client.FetchConfig(ctx)
	if err != nil {
		return fmt.Errorf("拉取配置失败: %w", err)
	}
	d, err := ValidateRemote(cfg, local, true)
	if err != nil {
		return err
	}
	if d.Interface != h.Interface {
		return reject("后端批准的接口 %q 与已打开的接口 %q 不一致", d.Interface, h.Interface)
	}
	addrs, subnets, err := LocalAddrs(d.Interface)
	if err != nil {
		return err
	}
	if err := client.Heartbeat(ctx, time.Now().UTC(), Version, Capabilities(d.Interface)); err != nil {
		return fmt.Errorf("心跳失败: %w", err)
	}
	state, err := LoadState(local.StateDir)
	if err != nil {
		return err
	}
	// 抓包随 ctx 结束；上报用独立上下文，抓包停止后给剩余批次有限时间送达。上报停止时同时停止抓包。
	capCtx, cancelCap := context.WithCancel(ctx)
	defer cancelCap()
	upCtx, cancelUp := context.WithCancel(context.Background())
	defer cancelUp()
	up := NewUploader(client, state, local, d.ConfigVersion)
	upErr := make(chan error, 1)
	go func() { upErr <- up.Run(upCtx); cancelCap() }()
	health := make(chan uplink.HealthWindow, 16)
	go sendControl(capCtx, client, d.Interface, health)

	policy := feature.NewAddressPolicy(addrs, subnets)
	p := pipeline.New(flow.NewTable(local.MTU, local.MaxFlows), feature.NewBuilder(policy, bootID), up.Add)
	w := &healthWindow{start: time.Now().UTC().Truncate(time.Millisecond), out: health}
	err = h.Run(capCtx, capture.LiveOptions{OnTick: func(now time.Time) {
		up.Flush()
		if now.Sub(w.start) >= HealthInterval {
			w.emit(now, p, up)
			if a, s, err := LocalAddrs(d.Interface); err == nil {
				policy.AddLocal(a, s)
			}
		}
	}}, p)
	up.Close()
	drain := time.AfterFunc(ShutdownDrain, cancelUp)
	e := <-upErr
	drain.Stop()
	if e != nil && !errors.Is(e, context.Canceled) {
		return e
	}
	return err
}

// ShutdownDrain 是停止抓包后等待剩余批次送达的上限。
const ShutdownDrain = 30 * time.Second

type healthWindow struct {
	start time.Time
	out   chan<- uplink.HealthWindow
}

// emit 在抓包线程上取快照；调用前已 Flush，因此 dropped ≤ ready ≤ seen。
func (w *healthWindow) emit(now time.Time, p *pipeline.Pipeline, up *Uploader) {
	// 后端列为 DATETIME(3)，MySQL 默认对亚毫秒四舍五入：上一窗口结束若进位，会大于本窗口开始而被判为重叠。
	// 边界按毫秒截断，使上一窗口结束与本窗口开始在库中逐位相等。
	now = now.Truncate(time.Millisecond)
	c, _, _ := p.Snapshot()
	dropped, qmax := up.TakeDropped()
	h := uplink.HealthWindow{WindowStart: w.start, WindowEnd: now, FlowsSeen: c.FlowsSeen,
		FlowsEmitted: c.Ready - dropped, FlowsDropped: dropped, QueueDepthMax: qmax, Errors: map[string]int64{}}
	w.start = now
	select {
	case w.out <- h:
	default: // 控制通道拥塞时放弃本窗口，不阻塞抓包
	}
}

func sendControl(ctx context.Context, c Control, iface string, health <-chan uplink.HealthWindow) {
	beat := time.NewTicker(HealthInterval)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case h := <-health:
			// 失败只影响监控，不影响抓包，也不重试；记录原因（只含状态码与错误码），避免静默丢窗口。
			if err := c.SubmitHealth(ctx, h); err != nil {
				fmt.Fprintf(os.Stderr, "sensor: 健康窗口 %s 提交失败: %v\n", h.WindowStart.Format(time.RFC3339Nano), err)
			}
		case now := <-beat.C:
			if err := c.Heartbeat(ctx, now.UTC(), Version, Capabilities(iface)); err != nil {
				fmt.Fprintf(os.Stderr, "sensor: 心跳提交失败: %v\n", err)
			}
		}
	}
}
