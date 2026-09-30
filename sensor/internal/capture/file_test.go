package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/pipeline"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// 合成 pcap → pcapgo 读取 → 流水线：验证微秒时间戳、线路长度与 EOF 时的 Flush 都按预期传递。
func TestReadFileRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 9, 30, 0, 0, 0, 123456000, time.UTC)
	host := netip.MustParseAddr("192.0.2.2")
	var frames []synth.Frame
	for i := 0; i < 101; i++ {
		peer := netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i%5)})
		ts := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		frames = append(frames,
			synth.Build(synth.Spec{TS: ts, Src: peer, Dst: host, SPort: uint16(30000 + i), DPort: 53, Proto: 17, Payload: 40}, 128),
			synth.Build(synth.Spec{TS: ts.Add(time.Millisecond), Src: host, Dst: peer, SPort: 53, DPort: uint16(30000 + i), Proto: 17, Payload: 90}, 128))
	}
	path := filepath.Join(t.TempDir(), "synthetic.pcap")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := synth.WritePcap(out, 128, frames); err != nil {
		t.Fatal(err)
	}
	out.Close()

	var records []feature.Record
	p := pipeline.New(flow.NewTable(1500, 10000),
		feature.NewBuilder(feature.NewAddressPolicy([]netip.Addr{host}, nil), "test"),
		func(rs []feature.Record) { records = append(records, rs...) })
	if err := ReadFile(path, p); err != nil {
		t.Fatal(err)
	}
	if len(records) != 101 {
		t.Fatalf("应输出 101 条记录: %d", len(records))
	}
	ready := 0
	for _, r := range records {
		if r.Status == feature.StatusReady {
			ready++
		}
	}
	last := records[100]
	if ready != 2 || last.Status != feature.StatusReady || last.CloseReason != "shutdown" {
		t.Fatalf("ready 条数或关闭原因错误: ready=%d last=%+v", ready, last)
	}
	f := last.Features
	// 单请求单应答：dur 0.001 s；spkts=dpkts=1 时 load 为 0；UDP 字节 = 20 + 8 + 载荷。
	if f.Dur != 0.001 || f.SBytes != 68 || f.DBytes != 118 || f.SLoad != 0 || f.Service != "dns" || f.CtDstLtm != 100 {
		t.Fatalf("特征错误: %+v", f)
	}
	if !last.FlowStartAt.Equal(t0.Add(10 * time.Second)) {
		t.Fatalf("微秒时间戳未保留: %v", last.FlowStartAt)
	}
	if d := p.Diagnostics(); d.Frames != 202 || d.ParseStatus["ok"] != 202 {
		t.Fatalf("诊断计数错误: %+v", d)
	}
}
