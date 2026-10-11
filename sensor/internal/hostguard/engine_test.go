package hostguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

var epoch = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
var host = netip.MustParseAddr("192.0.2.1")
var peer = netip.MustParseAddr("198.51.100.2")

func config(rows *[]Observation) Config {
	return Config{AssetID: "00000000-0000-4000-8000-000000000001", SensorID: "00000000-0000-4000-8000-000000000002", BootID: "00000000-0000-4000-8000-000000000003", CaptureScopeID: "00000000-0000-4000-8000-000000000004", Environment: "research", KeyEpoch: 1, PeerSecret: []byte("synthetic-golden-key-no-real-credential"), LocalAddresses: []netip.Addr{host}, Emit: func(v Emission) error { *rows = append(*rows, v.Observation); return nil }}
}
func pkt(ms int, out bool, syn, ack bool, seq uint64) Packet {
	p := Packet{Packet: packet.Packet{TS: epoch.Add(time.Duration(ms) * time.Millisecond), AF: 4, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, IPTotal: 40, IPHdr: 20, TCPHdr: 20, SYN: syn, ACK: ack}, CaptureSeq: seq, Seq: 100}
	if out {
		p.Src, p.Dst = host, peer
		p.SPort, p.DPort = 80, 40000
	}
	return p
}
func push(t *testing.T, e *Engine, p Packet) {
	t.Helper()
	if err := e.Push(p); err != nil {
		t.Fatal(err)
	}
}
func tick(t *testing.T, e *Engine, ms int) {
	t.Helper()
	if err := e.Tick(epoch.Add(time.Duration(ms) * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
}
func closeEngine(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCausalScheduleAndFutureInvariance(t *testing.T) {
	run := func(futureLength int) []Observation {
		var rows []Observation
		e, _ := New(config(&rows))
		push(t, e, pkt(0, false, true, false, 1))
		p := pkt(1000, true, false, true, 2)
		p.IPTotal = 60
		push(t, e, p)
		p = pkt(1100, false, false, true, 3)
		p.IPTotal = futureLength
		push(t, e, p)
		tick(t, e, 5100)
		tick(t, e, 10100)
		closeEngine(t, e)
		return rows
	}
	a, b := run(100), run(1400)
	if !reflect.DeepEqual(a[0], b[0]) {
		t.Fatal("未来包改变了已发布 prefix")
	}
	if len(a) != 3 || a[0].Features.PacketsInbound != 1 || a[0].Features.PacketsOutbound != 1 || a[0].Features.ElapsedMs != 1000 || a[1].Features.ElapsedMs != 5000 || *a[2].CloseReason != "eof" {
		t.Fatalf("不正确的快照: %+v", a)
	}
	if a[0].Contexts[0].PeerFlowStarts != 0 || a[0].Contexts[1].PeerFlowStarts != 1 || a[0].Contexts[1].CoverageMs != 1000 {
		t.Fatal("窗口必须为左开右闭且保留真实覆盖")
	}
}
func TestReorderLateAndSameTime(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	push(t, e, pkt(1000, false, false, true, 2))
	push(t, e, pkt(950, true, false, true, 3))
	push(t, e, pkt(1000, true, false, true, 4))
	tick(t, e, 1100)
	if len(rows) != 1 || rows[0].Features.PacketsInbound+rows[0].Features.PacketsOutbound != 4 {
		t.Fatal("水位未按时间和序号排序")
	}
	before, _ := json.Marshal(rows)
	push(t, e, pkt(1000, false, false, true, 5))
	after, _ := json.Marshal(rows)
	if string(before) != string(after) {
		t.Fatal("迟到修改了过去")
	}
	push(t, e, pkt(1100, false, false, true, 6))
	tick(t, e, 5100)
	if !rows[1].Quality.LatePacket || rows[1].Contexts[2].CoverageMs != 4000 {
		t.Fatal("迟到/coverage 缺陷未传播")
	}
	if err := e.Push(pkt(1200, false, false, true, 6)); err == nil {
		t.Fatal("重复 captureSeq 未拒绝")
	}
}
func TestHandshakeEpochAndContinuation(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	p := pkt(10, true, true, true, 2)
	p.Seq = 500
	p.Ack = 101
	push(t, e, p)
	p = pkt(20, false, false, true, 3)
	p.Seq = 101
	p.Ack = 501
	push(t, e, p)
	tick(t, e, 1100)
	if !*rows[0].Features.HandshakeSeen || rows[0].Direction != "inbound" {
		t.Fatal("握手不成立")
	}
	tick(t, e, 30200)
	push(t, e, pkt(31000, false, false, true, 4))
	tick(t, e, 32100)
	if rows[2].FlowID == rows[0].FlowID || rows[2].ParentConnectionID != rows[0].ParentConnectionID || !*rows[2].Features.HandshakeSeen {
		t.Fatal("idle 续段丢失 parent/握手")
	}
	p = pkt(32200, false, true, false, 5)
	p.Seq = 700
	push(t, e, p)
	tick(t, e, 33400)
	closeEngine(t, e)
	if *rows[3].CloseReason != "new_syn" || rows[4].ParentConnectionID == rows[0].ParentConnectionID {
		t.Fatal("新 SYN 应创建新 parent")
	}
}
func TestFinalWinsAtBoundaryAndTombstone(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	p := pkt(1000, true, false, true, 2)
	p.RST = true
	push(t, e, p)
	tick(t, e, 1100)
	if len(rows) != 1 || rows[0].Profile != "flow-final-v1" || *rows[0].CloseReason != "rst" {
		t.Fatal("边界应仅 final")
	}
	push(t, e, pkt(2000, false, false, true, 3))
	tick(t, e, 2100)
	if e.Stats["tombstone_packets"] != 1 {
		t.Fatal("未吸收尾包")
	}
	p = pkt(3000, false, true, false, 4)
	p.Seq = 800
	push(t, e, p)
	closeEngine(t, e)
	if rows[0].ParentConnectionID == rows[1].ParentConnectionID {
		t.Fatal("新 SYN 被墓碑吞掉")
	}
}
func TestProtocolNullAndUnknownDirection(t *testing.T) {
	for _, proto := range []uint8{6, 17, 1, 58, 99} {
		t.Run(fmt.Sprint(proto), func(t *testing.T) {
			var rows []Observation
			e, _ := New(config(&rows))
			p := pkt(0, false, false, false, 1)
			p.Proto = proto
			push(t, e, p)
			closeEngine(t, e)
			o := rows[0]
			if proto != 6 && o.Features.SynCount != nil {
				t.Fatal("非 TCP 必须 null")
			}
			if o.Features.IATMeanUs != nil {
				t.Fatal("单包 IAT 必须 null")
			}
			if proto != 17 && o.Direction != "unknown" {
				t.Fatal("未知方向不可猜测")
			}
			if o.Direction == "unknown" && (o.ServicePort != nil || o.TargetRef != nil) {
				t.Fatal("unknown 目标泄漏")
			}
		})
	}
}
func TestGapCapacityOffloadAndEOF(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	c.MaxFlows = 1
	e, _ := New(c)
	push(t, e, pkt(0, false, true, false, 1))
	p := pkt(500, false, true, false, 2)
	p.SPort = 40001
	push(t, e, p)
	tick(t, e, 1100)
	if !rows[0].Quality.CapacityDrop || rows[0].Contexts[2].CoverageMs != 500 {
		t.Fatal("容量缺陷未传播")
	}
	if err := e.Gap(epoch.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	p = pkt(2500, false, false, true, 3)
	p.Quality.OffloadSuspected = true
	push(t, e, p)
	closeEngine(t, e)
	o := rows[len(rows)-1]
	if !o.Quality.CaptureGap || !o.Quality.OffloadSuspected || *o.CloseReason != "eof" || !o.AsOf.Equal(p.TS) {
		t.Fatal("gap/offload/EOF 失真")
	}
}
func TestMaxLifetimeKeepsParentAndNoArtificialFlow(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	for i := 0; i <= 13; i++ {
		push(t, e, pkt(i*10000, false, i == 0, i != 0, uint64(i+1)))
	}
	closeEngine(t, e)
	var end *Observation
	for i := range rows {
		if rows[i].CloseReason != nil && *rows[i].CloseReason == "max_lifetime" {
			end = &rows[i]
		}
	}
	last := rows[len(rows)-1]
	if end == nil || end.Features.ElapsedMs != 120000 || last.ParentConnectionID != end.ParentConnectionID || last.FlowID == end.FlowID {
		t.Fatal("120 秒续段错误")
	}
}
func TestSYNRetryDoesNotStartNewParent(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	push(t, e, pkt(100, false, true, false, 2))
	tick(t, e, 1100)
	closeEngine(t, e)
	if *rows[0].Features.SynCount != 2 || rows[0].Contexts[1].PeerFlowStarts != 1 {
		t.Fatal("握手重传被当新连接")
	}
}
func TestTargetOnlyRenewedByNewPackets(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	c.Environment = "lab"
	zero := 0.
	c.ClockSkewMs = &zero
	calls := 0
	c.Lease = func(o Observation, _ Endpoints) (string, time.Time, error) {
		calls++
		return "00000000-0000-4000-8000-000000000005", o.LastPacketAt.Add(15 * time.Second), nil
	}
	e, _ := New(c)
	push(t, e, pkt(0, false, true, false, 1))
	tick(t, e, 1100)
	tick(t, e, 30100)
	if calls != 1 || rows[0].TargetRef == nil || rows[1].TargetRef != nil {
		t.Fatal("定时器续证或过期引用未清空")
	}
}

type liveFixture struct {
	frames []synth.Frame
	i      int
	now    time.Time
}

func (s *liveFixture) Next() ([]byte, gopacket.CaptureInfo, error) {
	if s.i == len(s.frames) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	f := s.frames[s.i]
	s.i++
	s.now = f.TS
	return f.Data, gopacket.CaptureInfo{Timestamp: f.TS, Length: f.WireLen, CaptureLength: len(f.Data)}, nil
}
func (s *liveFixture) Drops() (uint64, error) { return 0, nil }
func TestPCAPLiveParity(t *testing.T) {
	frames := []synth.Frame{}
	for i, ms := range []int{0, 500, 1000, 6000} {
		frames = append(frames, synth.Build(synth.Spec{TS: epoch.Add(time.Duration(ms) * time.Millisecond), Src: peer, Dst: host, SPort: 40000, DPort: 53, Proto: 17, Payload: 10 + i}, 256))
	}
	path := filepath.Join(t.TempDir(), "golden.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = synth.WritePcap(f, 256, frames); err != nil {
		t.Fatal(err)
	}
	f.Close()
	var fileRows, liveRows []Observation
	e, _ := New(config(&fileRows))
	if err = ReadPCAP(path, e); err != nil {
		t.Fatal(err)
	}
	e, _ = New(config(&liveRows))
	s := &liveFixture{frames: frames}
	if err = RunLive(context.Background(), s, e, func() time.Time { return s.now }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fileRows, liveRows) {
		t.Fatal("PCAP/live 快照不一致")
	}
}

func TestLiveClockSkewFollowsFreshMeasurement(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	skew, fresh := int64(-7), true
	c.ClockSkew = func() (int64, bool) { return skew, fresh }
	e, _ := New(c)
	push(t, e, pkt(0, false, true, false, 1))
	push(t, e, pkt(1000, true, false, true, 2))
	tick(t, e, 1200)
	fresh = false
	tick(t, e, 5100)
	closeEngine(t, e)
	if len(rows) < 2 || rows[0].Quality.ClockSkewMs == nil || *rows[0].Quality.ClockSkewMs != -7 {
		t.Fatalf("新鲜实测偏差必须写入快照: %+v", rows)
	}
	for _, o := range rows[1:] {
		if o.Quality.ClockSkewMs != nil {
			t.Fatal("测值过期后快照必须为 null，不能沿用旧值或填零")
		}
	}
	var offline []Observation
	e, _ = New(config(&offline))
	push(t, e, pkt(0, false, true, false, 1))
	closeEngine(t, e)
	if offline[0].Quality.ClockSkewMs != nil {
		t.Fatal("离线提取没有实时测值时必须保持 null")
	}
}
