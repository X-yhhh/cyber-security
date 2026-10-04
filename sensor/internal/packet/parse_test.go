package packet_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

var (
	t0 = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	a4 = netip.MustParseAddr("192.0.2.10")
	b4 = netip.MustParseAddr("192.0.2.2")
	a6 = netip.MustParseAddr("2001:db8::10")
	b6 = netip.MustParseAddr("2001:db8::2")
)

func parse(t *testing.T, s synth.Spec, snaplen int) (packet.Packet, packet.Status) {
	t.Helper()
	f := synth.Build(s, snaplen)
	return packet.ParseEthernet(f.Data, f.WireLen, f.TS)
}

func TestTCPWithMSSAndVLAN(t *testing.T) {
	p, st := parse(t, synth.Spec{TS: t0, Src: a4, Dst: b4, SPort: 40000, DPort: 443, Proto: 6,
		Flags: synth.SYN, MSS: 1460, VLAN: true}, 128)
	if st != packet.OK || !p.VLAN || !p.SYN || p.ACK || p.MSS != 1460 || p.IPTotal != 44 || p.TCPHdr != 24 {
		t.Fatalf("解析错误: st=%v %+v", st, p)
	}
	if p.SPort != 40000 || p.DPort != 443 || p.AF != 4 {
		t.Fatalf("端口或地址族错误: %+v", p)
	}
}

func TestZeroLengthFieldUsesWireLength(t *testing.T) {
	p, st := parse(t, synth.Spec{TS: t0, Src: a4, Dst: b4, SPort: 1, DPort: 2, Proto: 6, Flags: synth.ACK,
		Payload: 3000, ZeroLength: true}, 128)
	// 线路帧长 14 + 20 + 20 + 3000，IP 层长度 = 线路长度 − 14。
	if st != packet.OK || !p.TotalFromCap || p.IPTotal != 3040 {
		t.Fatalf("长度推算错误: st=%v total=%d", st, p.IPTotal)
	}
}

func TestSnaplenTruncatesTCPOptionsOnly(t *testing.T) {
	// 以太网 14 + IPv6 40 + TCP 24：snaplen 70 截断 TCP 选项，但端口与标志位仍可读。
	p, st := parse(t, synth.Spec{TS: t0, Src: a6, Dst: b6, SPort: 5, DPort: 22, Proto: 6,
		Flags: synth.SYN, MSS: 1440}, 70)
	if st != packet.OK || !p.TCPOptTrunc || p.MSS != 0 || p.DPort != 22 || p.AF != 6 {
		t.Fatalf("选项截断处理错误: st=%v %+v", st, p)
	}
}

func TestIPv6FragmentHeader(t *testing.T) {
	first, st := parse(t, synth.Spec{TS: t0, Src: a6, Dst: b6, SPort: 7, DPort: 53, Proto: 17, Payload: 1400,
		FragID: 99, MoreFrags: true}, 128)
	if st != packet.OK || !first.FirstFrag || first.FragID != 99 || first.Proto != 17 || first.IPHdr != 48 {
		t.Fatalf("IPv6 首片错误: %+v", first)
	}
	later, st := parse(t, synth.Spec{TS: t0, Src: a6, Dst: b6, Proto: 17, Payload: 200, FragID: 99,
		FragOffset: 176}, 128)
	if st != packet.OK || !later.LaterFrag || later.SPort != 0 {
		t.Fatalf("IPv6 后续分片错误: %+v", later)
	}
}

func TestShortAndNonIPFrames(t *testing.T) {
	if _, st := packet.ParseEthernet(make([]byte, 10), 10, t0); st != packet.Truncated {
		t.Fatalf("短帧应为 truncated: %v", st)
	}
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	if _, st := packet.ParseEthernet(arp, 42, t0); st != packet.NonIP {
		t.Fatalf("ARP 应为 non_ip: %v", st)
	}
	bad := synth.Build(synth.Spec{TS: t0, Src: a4, Dst: b4, Proto: 6, Flags: synth.ACK}, 128)
	bad.Data[14+20+12] = 0x10 // TCP 数据偏移 4 字节 < 20
	if _, st := packet.ParseEthernet(bad.Data, bad.WireLen, t0); st != packet.Malformed {
		t.Fatalf("TCP 头长非法应为 malformed: %v", st)
	}
}
