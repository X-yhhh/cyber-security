//go:build cgo || windows

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

// PCAPLive 仅打开明确白名单中的 Ethernet/RAW/回环接口；非混杂、立即读取、25ms超时。
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
	for _, err := range []error{in.SetSnapLen(65535), in.SetPromisc(false), in.SetTimeout(25 * time.Millisecond), in.SetImmediateMode(true)} {
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
	return s.ScopeService(local, peers, port, "local")
}

// ScopeService 显式登记服务在哪一端，允许对同一授权服务做客户端物理接口验收。
// 空值保持旧的本机服务语义；未知值拒绝，不能把端口扩大成两端任意服务。
func (s *PCAPLive) ScopeService(local, peers []netip.Addr, port uint16, endpoint string) error {
	filter, err := serviceScopeFilter(local, peers, port, endpoint)
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

// ScopeAllInbound 登记“本机全部入站 TCP”范围：只放行一端为登记本机地址、另一端为非本机地址的 TCP，
// 两个方向都保留，否则 SYN-ACK/RST/出站字节缺失，现场特征与离线提取不再同口径。
// 不接受对端或端口白名单，也不放行本机地址之间或与本机无关的流量；接口仍由 OpenPCAPLive 白名单限定。
func (s *PCAPLive) ScopeAllInbound(local []netip.Addr) error {
	filter, err := allInboundScopeFilter(local)
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

// MaxAllInboundAddresses 限制单个捕获域登记的本机地址数，避免生成无界 BPF。
const MaxAllInboundAddresses = 16

func allInboundScopeFilter(local []netip.Addr) (string, error) {
	if len(local) == 0 || len(local) > MaxAllInboundAddresses {
		return "", fmt.Errorf("缺少授权本机地址或地址过多")
	}
	hosts := make([]string, 0, len(local))
	seen := map[netip.Addr]bool{}
	for _, addr := range local {
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" || addr.Is4In6() || seen[addr] {
			return "", fmt.Errorf("授权地址无效")
		}
		seen[addr] = true
		hosts = append(hosts, "host "+addr.String())
	}
	src := "(src " + strings.Join(hosts, " or src ") + ")"
	dst := "(dst " + strings.Join(hosts, " or dst ") + ")"
	return "tcp and ((" + dst + " and not " + src + ") or (" + src + " and not " + dst + "))", nil
}

// ScopeLabPeer 只在明确的 lab 对端与登记端口间保留双向 TCP；不接受任意 BPF。
func (s *PCAPLive) ScopeLabPeer(local, peers []netip.Addr, ports []uint16) error {
	filter, err := labPeerScopeFilter(local, peers, ports)
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

func labPeerScopeFilter(local, peers []netip.Addr, ports []uint16) (string, error) {
	if len(local) != 1 || len(peers) != 1 || len(ports) == 0 || len(ports) > 128 {
		return "", fmt.Errorf("lab 必须限定一个本机、一个对端与最多 128 个端口")
	}
	if !local[0].Is4() || !peers[0].Is4() {
		return "", fmt.Errorf("lab 只支持 IPv4")
	}
	parts := make([]string, 0, len(ports))
	seen := map[uint16]bool{}
	for _, port := range ports {
		if seen[port] {
			return "", fmt.Errorf("lab 端口重复")
		}
		seen[port] = true
		f, err := serviceScopeFilter(local, peers, port, "local")
		if err != nil {
			return "", err
		}
		parts = append(parts, "("+f+")")
	}
	return strings.Join(parts, " or "), nil
}

func scopeFilter(local, peers []netip.Addr, port uint16) (string, error) {
	return serviceScopeFilter(local, peers, port, "local")
}

func serviceScopeFilter(local, peers []netip.Addr, port uint16, endpoint string) (string, error) {
	if endpoint != "" && endpoint != "local" && endpoint != "peer" {
		return "", fmt.Errorf("服务端点必须为 local 或 peer")
	}
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
			server, client := l, p
			if endpoint == "peer" {
				server, client = p, l
			}
			parts = append(parts, fmt.Sprintf("(src host %s and src port %d and dst host %s) or (src host %s and dst host %s and dst port %d)", server, port, client, client, server, port))
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
			return nil, gopacket.CaptureInfo{}, ErrCaptureFiltered
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
