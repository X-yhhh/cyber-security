package capture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/xyh/cyber-security/sensor/internal/pipeline"
	"github.com/xyh/cyber-security/sensor/internal/spec"
)

// FixedFilter 是唯一允许的 BPF 表达式。后端配置只能收窄接口范围，不能下发任意过滤串（fail-closed）。
const FixedFilter = "ip or ip6"

// LiveOptions 是实时抓包参数。Interface 必须同时出现在本机白名单 Allowed 中。
type LiveOptions struct {
	Interface   string
	Allowed     []string
	ReadTimeout time.Duration
	// OnTick 在抓包 goroutine 内每秒至少调用一次（读超时或跨过整秒时），
	// 用于在同一线程上取健康快照、刷新本机地址，避免并发访问流水线。
	OnTick func(now time.Time)
}

// ErrInterfaceNotAllowed 表示请求的接口不在本机授权白名单内。
var ErrInterfaceNotAllowed = errors.New("抓包接口不在本机授权白名单内")

// RunLive 在授权接口上以非混杂模式、snaplen 128 抓包，直到 ctx 取消；返回前 Close 流水线。
// 只读取头部，不写出任何报文或 pcap 文件。
func RunLive(ctx context.Context, opt LiveOptions, p *pipeline.Pipeline) error {
	if opt.Interface == "" || !slices.Contains(opt.Allowed, opt.Interface) {
		return ErrInterfaceNotAllowed
	}
	if opt.ReadTimeout <= 0 || opt.ReadTimeout > time.Second {
		opt.ReadTimeout = 500 * time.Millisecond
	}
	in, err := pcap.NewInactiveHandle(opt.Interface)
	if err != nil {
		return fmt.Errorf("无法打开接口: %w", err)
	}
	defer in.CleanUp()
	for _, set := range []error{in.SetSnapLen(spec.SnapLen), in.SetPromisc(false), in.SetTimeout(opt.ReadTimeout)} {
		if set != nil {
			return fmt.Errorf("抓包参数设置失败: %w", set)
		}
	}
	h, err := in.Activate()
	if err != nil {
		return fmt.Errorf("激活抓包失败（需要抓包权限）: %w", err)
	}
	defer h.Close()
	if h.LinkType() != layers.LinkTypeEthernet {
		return fmt.Errorf("接口链路类型 %v 不是以太网", h.LinkType())
	}
	if err := h.SetBPFFilter(FixedFilter); err != nil {
		return fmt.Errorf("设置过滤器失败: %w", err)
	}
	lastTick := time.Now()
	tick := func(now time.Time) {
		if now.Sub(lastTick) < time.Second {
			return
		}
		lastTick = now
		if opt.OnTick != nil {
			opt.OnTick(now)
		}
	}
	for {
		if ctx.Err() != nil {
			p.Close()
			return nil
		}
		data, ci, err := h.ReadPacketData()
		now := time.Now().UTC()
		switch {
		case err == nil:
			p.Frame(data, ci.Length, ci.Timestamp.UTC())
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			p.Tick(now)
		default:
			p.Close()
			return fmt.Errorf("抓包读取失败: %w", err)
		}
		tick(now)
	}
}
