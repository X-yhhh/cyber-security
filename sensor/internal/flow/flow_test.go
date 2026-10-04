package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

var (
	t0     = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	client = netip.MustParseAddr("192.0.2.10")
	server = netip.MustParseAddr("192.0.2.2")
)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

func feed(t *testing.T, tab *Table, specs ...synth.Spec) []Completed {
	t.Helper()
	var out []Completed
	for _, s := range specs {
		f := synth.Build(s, 128)
		p, st := packet.ParseEthernet(f.Data, f.WireLen, f.TS)
		if st != packet.OK {
			t.Fatalf("解析失败: %v", st)
		}
		out = append(out, tab.Accept(&p)...)
	}
	return out
}

func c2s(ms int, flags uint8, payload int) synth.Spec {
	return synth.Spec{TS: at(ms), Src: client, Dst: server, SPort: 40000, DPort: 80, Proto: 6, Flags: flags, Payload: payload}
}

func s2c(ms int, flags uint8, payload int) synth.Spec {
	return synth.Spec{TS: at(ms), Src: server, Dst: client, SPort: 80, DPort: 40000, Proto: 6, Flags: flags, Payload: payload}
}

func TestFullHandshakeAndFinClose(t *testing.T) {
	tab := NewTable(1500, 1000)
	out := feed(t, tab,
		c2s(0, synth.SYN, 0), s2c(20, synth.SYN|synth.ACK, 0), c2s(50, synth.ACK, 0),
		c2s(60, synth.ACK|synth.PSH, 100), s2c(80, synth.ACK|synth.PSH, 300),
		c2s(100, synth.FIN|synth.ACK, 0), s2c(120, synth.FIN|synth.ACK, 0))
	if len(out) != 1 || out[0].Reason != "tcp_fin" || out[0].ExportSeq != 1 {
		t.Fatalf("应在双向 FIN 后导出一条流: %+v", out)
	}
	f := out[0]
	// client：SYN、ACK、PSH|ACK(100)、FIN|ACK；server：SYN|ACK、PSH|ACK(300)、FIN|ACK。
	if f.Init.Addr != client || !f.HandshakeSeen || f.SPkts != 4 || f.DPkts != 3 {
		t.Fatalf("方向或计数错误: init=%v hs=%v s=%d d=%d", f.Init.Addr, f.HandshakeSeen, f.SPkts, f.DPkts)
	}
	if f.SBytes != 4*40+100 || f.DBytes != 3*40+300 {
		t.Fatalf("字节计数错误: %d %d", f.SBytes, f.DBytes)
	}
	synack, ackdat := f.Handshake()
	if synack != 0.02 || ackdat != 0.03 || f.Dur() != 0.12 {
		t.Fatalf("握手或时长错误: %v %v %v", synack, ackdat, f.Dur())
	}
	// 墓碑期内的尾随 ACK 只计数不建流；纯 SYN 立即开新流。
	feed(t, tab, c2s(1000, synth.ACK, 0))
	if tab.Active() != 0 || tab.Diag.PostClosePackets != 1 {
		t.Fatalf("墓碑期尾随报文应被吸收")
	}
	feed(t, tab, c2s(2000, synth.SYN, 0))
	if tab.Active() != 1 {
		t.Fatal("纯 SYN 应在墓碑期内开新流")
	}
}

func TestMidstreamStartHasNoHandshake(t *testing.T) {
	tab := NewTable(1500, 1000)
	feed(t, tab, s2c(0, synth.ACK, 100), c2s(10, synth.ACK, 0))
	out := tab.Flush(at(20))
	f := out[0]
	// 首包来自 server：它是 initiator，握手字段全为 0，handshakeSeen=false。
	if f.Init.Addr != server || f.HandshakeSeen || f.Reason != "shutdown" {
		t.Fatalf("中途接入流方向错误: %+v", f.Flow)
	}
	if s, a := f.Handshake(); s != 0 || a != 0 {
		t.Fatal("握手不完整时握手字段应为 0")
	}
}

func TestMaxLifetimeSplitKeepsInitiator(t *testing.T) {
	tab := NewTable(1500, 1000)
	var specs []synth.Spec
	specs = append(specs, c2s(0, synth.SYN, 0))
	for ms := 500; ms < 75_000; ms += 500 {
		specs = append(specs, s2c(ms, synth.ACK, 10))
	}
	out := feed(t, tab, specs...)
	var split []Completed
	for _, c := range out {
		if c.Reason == "max_lifetime" {
			split = append(split, c)
		}
	}
	if len(split) != 1 || split[0].Dur() >= 60 {
		t.Fatalf("应在 60 秒处切出一段: %d", len(split))
	}
	rest := tab.Flush(at(75_000))
	if len(rest) != 1 || rest[0].Segment != 1 || rest[0].Init.Addr != client || rest[0].HandshakeSeen {
		t.Fatalf("续段应继承 initiator: %+v", rest)
	}
	if rest[0].SPkts != 0 || rest[0].DPkts == 0 {
		t.Fatalf("续段方向计数错误: s=%d d=%d", rest[0].SPkts, rest[0].DPkts)
	}
}

func TestIdleTimeoutAndDeterministicSweepOrder(t *testing.T) {
	tab := NewTable(1500, 1000)
	other := netip.MustParseAddr("192.0.2.11")
	feed(t, tab,
		synth.Spec{TS: at(0), Src: other, Dst: server, SPort: 5353, DPort: 53, Proto: 17, Payload: 30},
		synth.Spec{TS: at(0), Src: client, Dst: server, SPort: 5353, DPort: 53, Proto: 17, Payload: 30})
	out := feed(t, tab, c2s(31_000, synth.SYN, 0))
	if len(out) != 2 || out[0].Reason != "idle_timeout" || out[0].Init.Addr != client || out[1].Init.Addr != other {
		t.Fatalf("UDP 30 秒空闲超时应按 (末包, 首包, 流键) 排序导出: %+v", out)
	}
	if out[0].ExportSeq != 1 || out[1].ExportSeq != 2 || out[0].DPkts != 0 {
		t.Fatal("导出序号或单向计数错误")
	}
}

func TestOversizeSegmentsSplitByMSS(t *testing.T) {
	tab := NewTable(1500, 1000)
	syn := c2s(0, synth.SYN, 0)
	syn.MSS = 1460
	synack := s2c(10, synth.SYN|synth.ACK, 0)
	synack.MSS = 1400
	// 4000 字节载荷的 GSO 大包：按 responder 通告的 MSS 1400 折算为 3 段。
	feed(t, tab, syn, synack, c2s(20, synth.ACK, 0), c2s(30, synth.ACK, 4000))
	f := tab.Flush(at(40))[0]
	// SYN 带 MSS 选项为 44 字节；纯 ACK 40 字节；大包折算为 3 段，每段各带 40 字节头。
	if f.SPkts != 2+3 || f.SBytes != 44+40+4000+3*40 || tab.Diag.OversizePackets != 1 {
		t.Fatalf("D11 折算错误: pkts=%d bytes=%d", f.SPkts, f.SBytes)
	}
}

func TestFragmentsAttachToFlowAndOrphansCounted(t *testing.T) {
	tab := NewTable(1500, 1000)
	first := synth.Spec{TS: at(0), Src: client, Dst: server, SPort: 5000, DPort: 161, Proto: 17, Payload: 1472,
		FragID: 7, MoreFrags: true}
	later := synth.Spec{TS: at(1), Src: client, Dst: server, Proto: 17, Payload: 500, FragID: 7, FragOffset: 185}
	orphan := synth.Spec{TS: at(2), Src: client, Dst: server, Proto: 17, Payload: 100, FragID: 9, FragOffset: 10}
	feed(t, tab, first, later, orphan)
	f := tab.Flush(at(10))[0]
	if f.SPkts != 2 || f.SBytes != 20+8+1472+20+500 || tab.Diag.OrphanFragments != 1 {
		t.Fatalf("分片归属错误: pkts=%d bytes=%d orphan=%d", f.SPkts, f.SBytes, tab.Diag.OrphanFragments)
	}
}

func TestCapacityDrop(t *testing.T) {
	tab := NewTable(1500, 1)
	feed(t, tab, c2s(0, synth.SYN, 0),
		synth.Spec{TS: at(1), Src: client, Dst: server, SPort: 1, DPort: 2, Proto: 17})
	if tab.Active() != 1 || tab.Diag.CapacityDrops != 1 {
		t.Fatal("超出容量的新流应被丢弃并计数")
	}
}

func TestOfflineLabelLengthsAndDefaultOff(t *testing.T) {
	tab := NewTable(1500, 1000)
	normal := feed(t, tab, c2s(0, synth.SYN, 0), s2c(1, synth.RST, 0))
	if normal[0].LabelAudit != nil {
		t.Fatal("在线默认不应生成标签旁路")
	}
	tab = NewTable(1500, 1000)
	tab.EnableLabelAudit()
	out := feed(t, tab, c2s(0, synth.SYN, 0), s2c(20, synth.SYN|synth.ACK, 0), c2s(30, synth.ACK, 4000), s2c(40, synth.RST, 1))
	if a := out[0].LabelAudit; a.SPayload != 4000 || a.DPayload != 1 || a.SPackets != 2 || a.DPackets != 2 || !a.Reliable {
		t.Fatalf("离线原始包计数不可被 MSS 分段折算: %+v", a)
	}
	if out[0].SPkts <= out[0].LabelAudit.SPackets {
		t.Fatal("测试应覆盖 D11 分段折算差异")
	}
}
