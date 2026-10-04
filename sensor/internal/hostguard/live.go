//go:build cgo

package hostguard

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// PCAPLive 仅打开明确白名单中的 Ethernet/RAW/回环接口；非混杂、100ms超时。
// 只输出头部统计；实际采集范围和时限由 live CLI 的显式授权配置限定。
type PCAPLive struct {
	h     *pcap.Handle
	scope *pcap.BPF
}

func OpenPCAPLive(iface string, allowed []string) (*PCAPLive, error) {
	if iface == "" || !slices.Contains(allowed, iface) {
		return nil, fmt.Errorf("接口未授权")
	}
	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	// 提取只保留头部事件，但必须瞬时读全报文才能区分真实截短与完整载荷。
	for _, err := range []error{in.SetSnapLen(65535), in.SetPromisc(false), in.SetTimeout(100 * time.Millisecond)} {
		if err != nil {
			return nil, err
		}
	}
	h, err := in.Activate()
	if err != nil {
		return nil, err
	}
	if !supportedLink(h.LinkType()) {
		h.Close()
		return nil, fmt.Errorf("不支持的链路类型")
	}
	if err = h.SetBPFFilter("ip or ip6"); err != nil {
		h.Close()
		return nil, err
	}
	return &PCAPLive{h: h}, nil
}
func (s *PCAPLive) Close() { s.h.Close() }

// Scope 从本机/对端及服务登记生成双向窄过滤器；不接受任意 BPF 或通配地址。
func (s *PCAPLive) Scope(local, peers []netip.Addr, port uint16) error {
	filter, err := scopeFilter(local, peers, port)
	if err != nil {
		return err
	}
	bpf, err := pcap.NewBPF(s.h.LinkType(), 65535, filter)
	if err != nil {
		return err
	}
	if err = s.h.SetBPFFilter(filter); err != nil {
		return err
	}
	s.scope = bpf
	return nil
}

func scopeFilter(local, peers []netip.Addr, port uint16) (string, error) {
	if len(local) == 0 || len(peers) == 0 || port == 0 {
		return "", fmt.Errorf("缺少授权本机/对端/服务")
	}
	for _, addr := range append(slices.Clone(local), peers...) {
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
			return "", fmt.Errorf("授权地址无效")
		}
	}
	parts := make([]string, 0, len(local)*len(peers))
	for _, l := range local {
		for _, p := range peers {
			if l == p || l.Is4() != p.Is4() {
				return "", fmt.Errorf("本机/对端范围不明确")
			}
			parts = append(parts, fmt.Sprintf("(src host %s and src port %d and dst host %s) or (src host %s and dst host %s and dst port %d)", l, port, p, p, l, port))
		}
	}
	return "tcp and (" + strings.Join(parts, " or ") + ")", nil
}
func (s *PCAPLive) Next() ([]byte, gopacket.CaptureInfo, error) {
	if s.scope == nil {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("采集范围未登记")
	}
	b, c, err := s.h.ReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		err = ErrCaptureTimeout
	}
	if err == nil {
		// 拒绝设置窄过滤前可能已入内核队列的范围外包，不能送入轨迹或特征。
		if !s.scope.Matches(c, b) {
			return nil, gopacket.CaptureInfo{}, ErrCaptureTimeout
		}
		return normalizeLink(b, c, s.h.LinkType())
	}
	return b, c, err
}
func (s *PCAPLive) Drops() (uint64, error) {
	v, err := s.h.Stats()
	if err != nil {
		return 0, err
	}
	return uint64(v.PacketsDropped + v.PacketsIfDropped), nil
}
