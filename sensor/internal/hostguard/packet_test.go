package hostguard

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xyh/cyber-security/sensor/internal/synth"
)

func TestStrictHeaderAndOffloadQuality(t *testing.T) {
	base := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Payload: 200}, 256)
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		wire int
		want string
	}{
		{"payload_snaplen", func(b []byte) []byte { return b[:54] }, base.WireLen, "ok"},
		{"tcp_truncated", func(b []byte) []byte { return b[:50] }, base.WireLen, "invalid_length"},
		{"ip_length_zero", func(b []byte) []byte { b[16] = 0; b[17] = 0; return b }, base.WireLen, "invalid_length"},
		{"wire_short", func(b []byte) []byte { return b }, 50, "invalid_length"},
		{"fragment", func(b []byte) []byte { b[20] = 0x20; return b }, base.WireLen, "fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.edit(append([]byte(nil), base.Data...))
			_, status := Parse(b, tc.wire, epoch, 1, 1500)
			if status != tc.want {
				t.Fatalf("want %s got %s", tc.want, status)
			}
		})
	}
	big := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Payload: 2000}, 256)
	p, status := Parse(big.Data, big.WireLen, epoch, 1, 1500)
	if status != "ok" || !p.Quality.OffloadSuspected {
		t.Fatal("卸载嫌疑不可掩盖")
	}
	udp := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 53, Proto: 17, Payload: 20}, 256)
	binary.BigEndian.PutUint16(udp.Data[38:40], 7)
	_, status = Parse(udp.Data, udp.WireLen, epoch, 1, 1500)
	if status != "invalid_udp_length" {
		t.Fatal("坏 UDP 长度未拒绝")
	}
}
func TestIPv6Observation(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	local := netip.MustParseAddr("2001:db8::1")
	c.LocalAddresses = []netip.Addr{local}
	e, _ := New(c)
	f := synth.Build(synth.Spec{TS: epoch, Src: netip.MustParseAddr("2001:db8::2"), Dst: local, SPort: 40000, DPort: 443, Proto: 17, Payload: 10}, 256)
	if err := e.Frame(f.Data, f.WireLen, f.TS, 1); err != nil {
		t.Fatal(err)
	}
	closeEngine(t, e)
	if rows[0].AddressFamily != "ipv6" || rows[0].Features.SynCount != nil || rows[0].TargetRef != nil {
		t.Fatal("IPv6 研究范围错误")
	}
}
