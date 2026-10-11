package hostguard

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// fakeClock 让 1 倍速回放在测试中瞬时完成：Sleep 只推进虚拟墙钟。
type fakeClock struct {
	now    time.Time
	sleeps time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	c.sleeps += d
	return nil
}

// replayFixture 覆盖握手、两个对端、超过 1/5 秒快照与 idle 定时器的空闲段、
// 100ms 内乱序、超出重排窗口的迟到包、UDP 和与本机无关的报文。
func replayFixture(t *testing.T) (string, []synth.Frame) {
	t.Helper()
	other := netip.MustParseAddr("203.0.113.9")
	at := func(ms int) time.Time { return epoch.Add(time.Duration(ms)*time.Millisecond + 123456*time.Nanosecond) }
	specs := []synth.Spec{
		{TS: at(0), Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.SYN},
		{TS: at(2), Src: host, Dst: peer, SPort: 80, DPort: 40000, Proto: 6, Flags: synth.SYN | synth.ACK},
		{TS: at(4), Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.ACK},
		{TS: at(60), Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.PSH | synth.ACK, Payload: 300},
		{TS: at(40), Src: host, Dst: peer, SPort: 80, DPort: 40000, Proto: 6, Flags: synth.ACK}, // 100ms 内乱序
		{TS: at(1500), Src: other, Dst: host, SPort: 51000, DPort: 22, Proto: 6, Flags: synth.SYN},
		{TS: at(1501), Src: host, Dst: other, SPort: 22, DPort: 51000, Proto: 6, Flags: synth.RST | synth.ACK},
		{TS: at(2600), Src: peer, Dst: host, SPort: 40001, DPort: 53, Proto: 17, Payload: 30},
		{TS: at(2700), Src: other, Dst: peer, SPort: 1, DPort: 2, Proto: 6, Flags: synth.SYN}, // 与本机无关
		{TS: at(8200), Src: host, Dst: peer, SPort: 80, DPort: 40000, Proto: 6, Flags: synth.PSH | synth.ACK, Payload: 900},
		{TS: at(8000), Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.ACK}, // 迟到 >100ms
		{TS: at(52000), Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.FIN | synth.ACK},
		{TS: at(52001), Src: host, Dst: peer, SPort: 80, DPort: 40000, Proto: 6, Flags: synth.FIN | synth.ACK},
		{TS: at(53000), Src: peer, Dst: host, SPort: 40002, DPort: 443, Proto: 6, Flags: synth.SYN},
	}
	frames := make([]synth.Frame, len(specs))
	for i, s := range specs {
		frames[i] = synth.Build(s, 256)
	}
	path := filepath.Join(t.TempDir(), "replay.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = synth.WritePcap(f, 256, frames); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path, frames
}

func unshift(o Observation, d time.Duration) Observation {
	o.FirstSeenAt = o.FirstSeenAt.Add(-d)
	o.LastPacketAt = o.LastPacketAt.Add(-d)
	o.AsOf = o.AsOf.Add(-d)
	o.EmittedAt = time.Time{}
	if o.TargetExpiresAt != nil {
		v := o.TargetExpiresAt.Add(-d)
		o.TargetExpiresAt = &v
	}
	return o
}

func TestReplayMatchesOfflineFieldByField(t *testing.T) {
	path, frames := replayFixture(t)
	var offline, replay []Observation
	e, _ := New(config(&offline))
	if err := ReadPCAP(path, e); err != nil {
		t.Fatal(err)
	}
	wall := time.Date(2026, 10, 8, 9, 30, 15, 987654321, time.UTC)
	clock := &fakeClock{now: wall}
	var emittedWall []time.Time
	cfg := config(&replay)
	inner := cfg.Emit
	cfg.Emit = func(v Emission) error { emittedWall = append(emittedWall, clock.now); return inner(v) }
	r, _ := New(cfg)
	var samples []LiveSample
	res, err := ReplayPCAP(context.Background(), path, r, ReplayOptions{Clock: clock, Observe: func(s LiveSample) { samples = append(samples, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Offset%time.Second != 0 || res.Packets != uint64(len(frames)) || !res.SourceFirst.Equal(frames[0].TS.Truncate(time.Microsecond)) {
		t.Fatalf("平移或计数错误: %+v", res)
	}
	if first := frames[0].TS.Truncate(time.Microsecond).Add(res.Offset); first.Before(wall) || first.Sub(wall) >= 2*time.Second {
		t.Fatalf("首包平移后应在启动后 2 秒内: %v", first.Sub(wall))
	}
	// 1 倍速：虚拟墙钟推进量等于首包到末包的原始跨度（末包之后不再等待）。
	if span := frames[len(frames)-1].TS.Sub(frames[0].TS); clock.now.Sub(frames[0].TS.Truncate(time.Microsecond).Add(res.Offset)) != span {
		t.Fatalf("回放速度不是 1 倍: %v vs %v", clock.now.Sub(frames[0].TS.Truncate(time.Microsecond).Add(res.Offset)), span)
	}
	if len(offline) == 0 || len(offline) != len(replay) {
		t.Fatalf("观察数量不一致 %d/%d", len(offline), len(replay))
	}
	for i := range offline {
		got := unshift(replay[i], res.Offset)
		want := offline[i]
		want.EmittedAt = time.Time{}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("第 %d 条回放观察与离线不一致\n got=%+v\nwant=%+v", i, got, want)
		}
		// emittedAt 是真实墙钟，不早于事件时间；除文件末尾 eof 外，Tick 使快照在重排期+一个 Tick 内发出。
		if !replay[i].EmittedAt.Equal(emittedWall[i].UTC().Truncate(time.Microsecond)) && !replay[i].EmittedAt.Equal(replay[i].AsOf) {
			t.Fatalf("emittedAt 未取墙钟: %v", replay[i].EmittedAt)
		}
		if delay := emittedWall[i].Sub(replay[i].AsOf); delay < 0 || delay > 250*time.Millisecond {
			t.Fatalf("第 %d 条快照发出延迟 %v，Tick 未按时推进", i, delay)
		}
	}
	if !reflect.DeepEqual(e.Stats, r.Stats) || r.Stats["late_packets"] != 1 {
		t.Fatalf("统计不一致: %v / %v", e.Stats, r.Stats)
	}
	if len(samples) == 0 || samples[len(samples)-1].PacketsSeen != uint64(len(frames)) || samples[len(samples)-1].DropsKnown {
		t.Fatal("回放健康样本必须计数且历史丢包为未知")
	}
}

func TestReplayPartitionAndCancel(t *testing.T) {
	path, frames := replayFixture(t)
	var offline, replay []Observation
	start, end := frames[5].TS, frames[9].TS
	e, _ := New(config(&offline))
	seq := uint64(0)
	if err := WalkPCAP(path, func(b []byte, ci gopacket.CaptureInfo, s uint64) error {
		seq = s
		if ci.Timestamp.Before(start) || ci.Timestamp.After(end) {
			return nil
		}
		return e.Frame(b, ci.Length, ci.Timestamp, s)
	}); err != nil {
		t.Fatal(err)
	}
	_ = seq
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	r, _ := New(config(&replay))
	res, err := ReplayPCAP(context.Background(), path, r, ReplayOptions{Clock: &fakeClock{now: epoch.Add(400 * 24 * time.Hour)}, Start: start, End: end})
	if err != nil {
		t.Fatal(err)
	}
	if len(offline) != len(replay) || len(replay) == 0 {
		t.Fatalf("分区观察数量不一致 %d/%d", len(offline), len(replay))
	}
	for i := range offline {
		want := offline[i]
		want.EmittedAt = time.Time{}
		if !reflect.DeepEqual(unshift(replay[i], res.Offset), want) {
			t.Fatalf("分区第 %d 条不一致", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := New(config(&[]Observation{}))
	if _, err := ReplayPCAP(ctx, path, c, ReplayOptions{Clock: &fakeClock{now: epoch}}); err == nil {
		t.Fatal("取消的回放不能报告完成")
	}
	used, _ := New(config(&[]Observation{}))
	_ = used.Tick(epoch)
	if _, err := ReplayPCAP(context.Background(), path, used, ReplayOptions{Clock: &fakeClock{now: epoch}}); err == nil {
		t.Fatal("已使用的引擎不能用于回放")
	}
	empty, _ := New(config(&[]Observation{}))
	if _, err := ReplayPCAP(context.Background(), path, empty, ReplayOptions{Clock: &fakeClock{now: epoch}, Start: epoch.Add(time.Hour)}); err == nil {
		t.Fatal("空分区不能报告完成")
	}
}

// 采集起点早于首包：上下文覆盖从起点算，回放与先 Tick 起点的离线提取逐字段一致，1 倍速等待包含预热。
func TestReplayCaptureStartWarmup(t *testing.T) {
	path, frames := replayFixture(t)
	capture := frames[0].TS.Truncate(time.Microsecond).Add(-30 * time.Second)
	var offline, replay []Observation
	e, _ := New(config(&offline))
	if err := e.Tick(capture); err != nil {
		t.Fatal(err)
	}
	if err := ReadPCAP(path, e); err != nil {
		t.Fatal(err)
	}
	wall := time.Date(2026, 10, 8, 9, 30, 15, 987654321, time.UTC)
	clock := &fakeClock{now: wall}
	r, _ := New(config(&replay))
	res, err := ReplayPCAP(context.Background(), path, r, ReplayOptions{Clock: clock, CaptureStart: capture})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SourceFirst.Equal(frames[0].TS.Truncate(time.Microsecond)) || clock.sleeps < 30*time.Second {
		t.Fatalf("预热未按 1 倍速等待或首包记录错误: %+v sleeps=%v", res, clock.sleeps)
	}
	if len(offline) == 0 || len(offline) != len(replay) {
		t.Fatalf("观察数量不一致 %d/%d", len(offline), len(replay))
	}
	for i := range offline {
		want := offline[i]
		want.EmittedAt = time.Time{}
		if got := unshift(replay[i], res.Offset); !reflect.DeepEqual(got, want) {
			t.Fatalf("第 %d 条不一致", i)
		}
	}
	if offline[0].Contexts[0].CoverageMs != 1000 || offline[0].Contexts[2].CoverageMs != 30000 {
		t.Fatalf("预热后首个快照的覆盖应为完整窗口: %+v", offline[0].Contexts)
	}
	late, _ := New(config(&replay))
	if _, err := ReplayPCAP(context.Background(), path, late, ReplayOptions{Clock: &fakeClock{now: wall}, CaptureStart: frames[0].TS.Add(time.Second)}); err == nil {
		t.Fatal("采集起点晚于首包必须拒绝")
	}
}
