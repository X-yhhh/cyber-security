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

func TestLabPeerBPFKeepsBothDirectionsAndRejectsOtherEndpoints(t *testing.T) {
	local, remote := netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("100.64.0.20")
	f, err := labPeerScopeFilter([]netip.Addr{local}, []netip.Addr{remote}, []uint16{55280, 55300})
	if err != nil {
		t.Fatal(err)
	}
	bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		src, dst netip.Addr
		sp, dp   uint16
		want     bool
	}{
		{remote, local, 40000, 55280, true}, {local, remote, 55280, 40000, true},
		{remote, local, 40000, 22, false}, {remote, local, 55280, 40000, false},
		{netip.MustParseAddr("100.64.0.21"), local, 40000, 55280, false},
	} {
		frame := synth.Build(synth.Spec{TS: epoch, Src: tc.src, Dst: tc.dst, SPort: tc.sp, DPort: tc.dp, Proto: 6, Flags: synth.SYN}, 256)
		if bpf.Matches(gopacket.CaptureInfo{Length: frame.WireLen, CaptureLength: len(frame.Data)}, frame.Data) != tc.want {
			t.Fatalf("过滤范围错误: %+v", tc)
		}
	}
	for _, ports := range [][]uint16{nil, {0}, {55280, 55280}, make([]uint16, 129)} {
		if _, err := labPeerScopeFilter([]netip.Addr{local}, []netip.Addr{remote}, ports); err == nil {
			t.Fatal("无效范围未拒绝")
		}
	}
}
