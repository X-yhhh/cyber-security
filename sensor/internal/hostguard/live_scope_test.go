//go:build cgo || windows

package hostguard

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/xyh/cyber-security/sensor/internal/synth"
	"net/netip"
	"testing"
)

// 实际编译 BPF 并匹配双向报文，保证同对端其他服务及第三方地址不会被纳入授权。
func TestLiveScopeMatchesOnlyRegisteredService(t *testing.T) {
	l, p := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	filter, err := scopeFilter([]netip.Addr{l}, []netip.Addr{p}, 80)
	if err != nil {
		t.Fatal(err)
	}
	bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		src, dst netip.Addr
		sp, dp   uint16
		allowed  bool
	}{
		{p, l, 40000, 80, true}, {l, p, 80, 40000, true},
		{p, l, 80, 8080, false}, {l, p, 8080, 80, false},
		{netip.MustParseAddr("127.0.0.3"), l, 40000, 80, false},
	} {
		frame := synth.Build(synth.Spec{TS: epoch, Src: tc.src, Dst: tc.dst, SPort: tc.sp, DPort: tc.dp, Proto: 6, Flags: synth.SYN}, 65535)
		if bpf.Matches(gopacket.CaptureInfo{CaptureLength: len(frame.Data), Length: frame.WireLen}, frame.Data) != tc.allowed {
			t.Fatal("授权 BPF 范围错误")
		}
	}
	// 同一报文在客户端抓包时，服务必须明确登记为 peer；不得放行本机同号服务。
	filter, err = serviceScopeFilter([]netip.Addr{p}, []netip.Addr{l}, 80, "peer")
	if err != nil {
		t.Fatal(err)
	}
	peerBPF, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		t.Fatal(err)
	}
	for _, ports := range [][3]uint16{{40000, 80, 1}, {80, 40000, 0}, {40000, 81, 0}} {
		frame := synth.Build(synth.Spec{TS: epoch, Src: p, Dst: l, SPort: ports[0], DPort: ports[1], Proto: 6, Flags: synth.SYN}, 65535)
		if peerBPF.Matches(gopacket.CaptureInfo{CaptureLength: len(frame.Data), Length: frame.WireLen}, frame.Data) != (ports[2] == 1) {
			t.Fatal("peer 服务授权 BPF 范围错误")
		}
	}
	if _, err = serviceScopeFilter([]netip.Addr{l}, []netip.Addr{p}, 80, "any"); err == nil {
		t.Fatal("服务端点不明确未拒绝")
	}
	for _, tc := range []struct {
		locals, peers []netip.Addr
		port          uint16
	}{
		{nil, []netip.Addr{p}, 80}, {[]netip.Addr{l}, nil, 80},
		{[]netip.Addr{l}, []netip.Addr{l}, 80}, {[]netip.Addr{l}, []netip.Addr{p}, 0},
	} {
		if _, err := scopeFilter(tc.locals, tc.peers, tc.port); err == nil {
			t.Fatal("未明确范围未拒绝")
		}
	}
}
