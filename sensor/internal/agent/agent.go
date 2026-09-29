package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
func RunLive(ctx context.Context, local LocalConfig, client *uplink.Client, bootID string) error {
	cfg, err := client.FetchConfig(ctx)
	if err != nil {
		return fmt.Errorf("拉取配置失败: %w", err)
	}
	d, err := ValidateRemote(cfg, local, true)
	if err != nil {
		return err
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	up := NewUploader(client, state, local, d.ConfigVersion)
	upErr := make(chan error, 1)
	go func() { upErr <- up.Run(ctx); cancel() }()
	health := make(chan uplink.HealthWindow, 16)
	go sendControl(ctx, client, d.Interface, health)

	policy := feature.NewAddressPolicy(addrs, subnets)
	p := pipeline.New(flow.NewTable(local.MTU, local.MaxFlows), feature.NewBuilder(policy, bootID), up.Add)
	w := &healthWindow{start: time.Now().UTC(), out: health}
	err = capture.RunLive(ctx, capture.LiveOptions{Interface: d.Interface, Allowed: local.AllowedInterfaces,
		OnTick: func(now time.Time) {
			up.Flush()
			if now.Sub(w.start) >= HealthInterval {
				w.emit(now, p, up)
				if a, s, err := LocalAddrs(d.Interface); err == nil {
					policy.AddLocal(a, s)
				}
			}
		}}, p)
	up.Close()
	if e := <-upErr; e != nil && !errors.Is(e, context.Canceled) {
		return e
	}
	return err
}

type healthWindow struct {
	start time.Time
	out   chan<- uplink.HealthWindow
}

// emit 在抓包线程上取快照；调用前已 Flush，因此 dropped ≤ ready ≤ seen。
func (w *healthWindow) emit(now time.Time, p *pipeline.Pipeline, up *Uploader) {
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
			_ = c.SubmitHealth(ctx, h) // 失败只影响监控，不影响抓包；由后端心跳超时告警
		case now := <-beat.C:
			_ = c.Heartbeat(ctx, now.UTC(), Version, Capabilities(iface))
		}
	}
}
