package hostguard

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

func TestLoopbackAFByteOrderAndLengths(t *testing.T) {
	f := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.SYN, Payload: 30}, 256)
	for _, tc := range []struct {
		link  layers.LinkType
		order binary.ByteOrder
		af    uint32
		valid bool
	}{
		{layers.LinkTypeNull, binary.LittleEndian, 2, true}, {layers.LinkTypeNull, binary.BigEndian, 2, true},
		{layers.LinkTypeLoop, binary.BigEndian, 2, true}, {layers.LinkTypeLoop, binary.LittleEndian, 2, false},
		{layers.LinkTypeNull, binary.LittleEndian, 999, false}, {layers.LinkTypeNull, binary.LittleEndian, 30, false},
	} {
		b := make([]byte, 4)
		tc.order.PutUint32(b, tc.af)
		b = append(b, f.Data[14:]...)
		ci := gopacket.CaptureInfo{Timestamp: epoch, Length: f.WireLen - 10, CaptureLength: len(b)}
		got, info, err := normalizeLink(b, ci, tc.link)
		if (err == nil) != tc.valid {
			t.Fatalf("AF %d 链路 %d: %v", tc.af, tc.link, err)
		}
		if tc.valid && (!reflect.DeepEqual(got[14:], f.Data[14:]) || info.Length != f.WireLen || info.Timestamp != epoch || info.CaptureLength != len(got)) {
			t.Fatal("回环适配改变原 IP 或线路长度")
		}
	}
}

func TestLiveTraceReplaysIdenticalClockAndWatermark(t *testing.T) {
	var live, replay []Observation
	frames := []synth.Frame{}
	for i, ms := range []int{0, 500, 1000, 6000, 37000} {
		frames = append(frames, synth.Build(synth.Spec{TS: epoch.Add(time.Duration(ms) * time.Millisecond), Src: peer, Dst: host, SPort: 40000, DPort: 53, Proto: 17, Payload: 10 + i}, 256))
	}
	e, _ := New(config(&live))
	s := &liveFixture{frames: frames}
	var events []LiveEvent
	if err := RunLiveTrace(context.Background(), s, e, func() time.Time { return s.now }, func(v LiveEvent) error {
		// 经 JSON 往返模拟私有文件，Packet 格式无载荷成员。
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var decoded LiveEvent
		if err = json.Unmarshal(b, &decoded); err != nil {
			return err
		}
		events = append(events, decoded)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := New(config(&replay))
	for _, v := range events {
		if err := r.ApplyLiveEvent(v); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(live, replay) || !reflect.DeepEqual(e.Stats, r.Stats) {
		t.Fatal("同包轨迹时钟/水位/观察未一致")
	}
}

// 独立健康采样不得改变同一捕获序列的模型观察、特征或累计引擎统计。
func TestLiveObserverPreservesObservations(t *testing.T) {
	var plain, observed []Observation
	var frames []synth.Frame
	for i, ms := range []int{0, 500, 1000, 6000, 37000} {
		frames = append(frames, synth.Build(synth.Spec{TS: epoch.Add(time.Duration(ms) * time.Millisecond), Src: peer, Dst: host,
			SPort: 40000, DPort: 53, Proto: 17, Payload: 10 + i}, 256))
	}
	a, _ := New(config(&plain))
	s := &liveFixture{frames: frames, now: epoch}
	if err := RunLive(context.Background(), s, a, func() time.Time { return s.now }); err != nil {
		t.Fatal(err)
	}
	b, _ := New(config(&observed))
	s = &liveFixture{frames: frames, now: epoch}
	var samples []LiveSample
	if err := RunLiveObserved(context.Background(), s, b, func() time.Time { return s.now }, nil, func(v LiveSample) error {
		samples = append(samples, v)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, observed) || !reflect.DeepEqual(a.Stats, b.Stats) {
		t.Fatal("健康采样改变了观察或引擎统计")
	}
	if len(samples) != len(frames)+2 || samples[0].PacketsSeen != 0 || samples[len(samples)-1].PacketsSeen != uint64(len(frames)) {
		t.Fatal("首包前基线或退出样本缺失")
	}
}

func TestRawIPParityAndUnknownLinkRejected(t *testing.T) {
	f := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.SYN, Payload: 30}, 256)
	var expected []Observation
	e, _ := New(config(&expected))
	if err := e.Frame(f.Data, f.WireLen, f.TS, 1); err != nil {
		t.Fatal(err)
	}
	closeEngine(t, e)
	for _, link := range []uint32{12, 101, 999} {
		path := filepath.Join(t.TempDir(), "raw.pcap")
		h := make([]byte, 40)
		binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
		binary.LittleEndian.PutUint16(h[4:], 2)
		binary.LittleEndian.PutUint16(h[6:], 4)
		binary.LittleEndian.PutUint32(h[16:], 256)
		binary.LittleEndian.PutUint32(h[20:], link)
		binary.LittleEndian.PutUint32(h[24:], uint32(epoch.Unix()))
		binary.LittleEndian.PutUint32(h[32:], uint32(len(f.Data)-14))
		binary.LittleEndian.PutUint32(h[36:], uint32(f.WireLen-14))
		if err := os.WriteFile(path, append(h, f.Data[14:]...), 0600); err != nil {
			t.Fatal(err)
		}
		var got []Observation
		e, _ = New(config(&got))
		err := ReadPCAP(path, e)
		if link == 999 {
			if err == nil {
				t.Fatal("未知链路未拒绝")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatal("RAW/Ethernet 特征不一致")
		}
	}
}
func TestTruncatedContainerFailsWithoutSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0600); err != nil {
		t.Fatal(err)
	}
	var rows []Observation
	e, _ := New(config(&rows))
	if err := ReadPCAP(path, e); err == nil {
		t.Fatal("损坏容器未拒绝")
	}
}
func TestMissingVectorAndCapacityBudgets(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	c.MaxBufferedPackets = 1
	e, _ := New(c)
	p := pkt(0, false, false, false, 1)
	p.Proto = 17
	push(t, e, p)
	p = pkt(50, false, false, false, 2)
	p.Proto = 17
	push(t, e, p)
	closeEngine(t, e)
	if len(rows) != 1 || !rows[0].Quality.CapacityDrop || e.Stats["buffer_drops"] != 1 {
		t.Fatal("缓冲容量未有界拒绝")
	}
	v, err := ModelVector(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := 9; i <= 15; i++ {
		if v.Missing[i] != 1 || v.Values[i] != 0 {
			t.Fatal("结构性缺失 mask 错误")
		}
	}
	if v.Missing[1] != 0 || v.Values[1] != 0 {
		t.Fatal("实测零值被当缺失")
	}
	rows = nil
	c = config(&rows)
	c.MaxContextEvents = 1
	e, _ = New(c)
	push(t, e, pkt(0, false, true, false, 1))
	push(t, e, pkt(500, false, false, true, 2))
	tick(t, e, 1100)
	if !rows[0].Quality.CapacityDrop || rows[0].Contexts[2].CoverageMs != 500 {
		t.Fatal("上下文容量未重置")
	}
	rows = nil
	c = config(&rows)
	c.MaxConnections = 1
	e, _ = New(c)
	push(t, e, pkt(0, false, true, false, 1))
	p = pkt(500, false, true, false, 2)
	p.SPort++
	push(t, e, p)
	tick(t, e, 1100)
	if e.Stats["connection_drops"] != 1 || !rows[0].Quality.CapacityDrop {
		t.Fatal("连接身份表超限未拒绝")
	}
}

// 队列中包的读取墙钟远晚于包时间，也不能把正常顺序包标成迟到；真正乱序仍拒绝。
func TestBufferedPacketsDoNotAdvanceWallClockWatermark(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   []int
		late bool
	}{
		{"buffered", []int{0, 50, 100, 200}, false},
		{"late", []int{0, 500, 10, 600}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []Observation
			e, _ := New(config(&rows))
			s := &liveFixture{}
			for _, ms := range tc.ms {
				s.frames = append(s.frames, synth.Build(synth.Spec{TS: epoch.Add(time.Duration(ms) * time.Millisecond), Src: peer, Dst: host, SPort: 40000, DPort: 53, Proto: 17, Payload: 10}, 256))
			}
			if err := RunLive(context.Background(), s, e, func() time.Time { return epoch.Add(5 * time.Second) }); err != nil {
				t.Fatal(err)
			}
			if (e.Stats["late_packets"] > 0) != tc.late {
				t.Fatalf("迟到判定错误: %v", e.Stats)
			}
		})
	}
}
