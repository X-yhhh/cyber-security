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

// ErrInterfaceNotAllowed 表示请求的接口不在本机授权白名单内。
var ErrInterfaceNotAllowed = errors.New("抓包接口不在本机授权白名单内")

// LiveHandle 是已激活的抓包句柄：非混杂、snaplen 128、固定 BPF。
//
// 需要特权时由调用方以 root 打开，随后立即降权（privdrop）；已打开的 BPF 描述符在降权后仍可读取。
type LiveHandle struct {
	Interface string
	h         *pcap.Handle
}

// OpenLive 打开授权接口。iface 必须出现在本机白名单 allowed 中。只读取头部，不写出任何报文。
func OpenLive(iface string, allowed []string) (*LiveHandle, error) {
	if iface == "" || !slices.Contains(allowed, iface) {
		return nil, ErrInterfaceNotAllowed
	}
	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("无法打开接口: %w", err)
	}
	defer in.CleanUp()
	for _, set := range []error{in.SetSnapLen(spec.SnapLen), in.SetPromisc(false), in.SetTimeout(500 * time.Millisecond)} {
		if set != nil {
			return nil, fmt.Errorf("抓包参数设置失败: %w", set)
		}
	}
	h, err := in.Activate()
	if err != nil {
		return nil, fmt.Errorf("激活抓包失败（需要抓包权限）: %w", err)
	}
	if h.LinkType() != layers.LinkTypeEthernet {
		h.Close()
		return nil, fmt.Errorf("接口链路类型 %v 不是以太网", h.LinkType())
	}
	if err := h.SetBPFFilter(FixedFilter); err != nil {
		h.Close()
		return nil, fmt.Errorf("设置过滤器失败: %w", err)
	}
	return &LiveHandle{Interface: iface, h: h}, nil
}

// Close 关闭句柄。
func (l *LiveHandle) Close() { l.h.Close() }

// Drops 返回内核与接口层累计丢包数（diagnostics 用）。
func (l *LiveHandle) Drops() (kernel, iface int, err error) {
	s, err := l.h.Stats()
	if err != nil {
		return 0, 0, err
	}
	return s.PacketsDropped, s.PacketsIfDropped, nil
}

// LiveOptions 是读取循环参数。
type LiveOptions struct {
	// OnTick 在抓包 goroutine 内每秒至少调用一次，用于在同一线程上取健康快照、刷新本机地址，
	// 避免并发访问流水线。
	OnTick func(now time.Time)
}

// Run 读取报文直到 ctx 取消；返回前 Close 流水线。读超时时用墙钟推进空闲流导出。
func (l *LiveHandle) Run(ctx context.Context, opt LiveOptions, p *pipeline.Pipeline) error {
	lastTick := time.Now()
	for {
		if ctx.Err() != nil {
			p.Close()
			return nil
		}
		data, ci, err := l.h.ReadPacketData()
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
		if now.Sub(lastTick) >= time.Second {
			lastTick = now
			if opt.OnTick != nil {
				opt.OnTick(now)
			}
		}
	}
}
