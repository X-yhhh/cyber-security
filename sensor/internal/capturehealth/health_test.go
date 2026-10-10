package capturehealth

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

var t0 = time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)

func ident() Identity {
	return Identity{AssetID: "00000000-0000-4000-8000-000000000001", SensorID: "00000000-0000-4000-8000-000000000002", CaptureScopeID: "00000000-0000-4000-8000-000000000004", ConfigSha256: fmt.Sprintf("%064x", 1), BuildSha256: fmt.Sprintf("%064x", 2)}
}

func observer(t *testing.T, out *[]Window) *Observer {
	t.Helper()
	n := 0
	o, err := New(ident(), Options{Skew: func() (int64, bool) { return 3, true }, NewID: func() string { n++; return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }, Emit: func(w Window) error { *out = append(*out, w); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// verify 移植后端 GuardHealth.verify 的判定顺序，用于证明理想条件下窗口可被服务端认定为 healthy。
func verify(b, prev *Window, prevHash string, now time.Time) string {
	end, _ := time.Parse(time.RFC3339Nano, b.IntervalEnd)
	start, _ := time.Parse(time.RFC3339Nano, b.IntervalStart)
	if !start.Before(end) || end.Sub(start) > MaxWindow {
		return "INVALID_HEALTH_WINDOW"
	}
	if end.After(now) || now.Sub(end) > 10*time.Second {
		return "HEALTH_DELAY_EXCEEDED"
	}
	if b.ClockSkewMs == nil || *b.ClockSkewMs > 1000 || *b.ClockSkewMs < -1000 {
		return "CLOCK_UNTRUSTED"
	}
	if b.CaptureGap {
		return "CAPTURE_GAP"
	}
	for _, f := range [][2]*int64{{b.CounterStart.PacketsSeen, b.CounterEnd.PacketsSeen}, {b.CounterStart.KernelDrops, b.CounterEnd.KernelDrops}, {b.CounterStart.CapacityDrops, b.CounterEnd.CapacityDrops}} {
		if f[0] == nil || f[1] == nil {
			return "COUNTER_UNKNOWN"
		}
	}
	if *b.CounterEnd.PacketsSeen < *b.CounterStart.PacketsSeen || *b.CounterEnd.KernelDrops != *b.CounterStart.KernelDrops || *b.CounterEnd.CapacityDrops != *b.CounterStart.CapacityDrops {
		return "CAPTURE_DROPS"
	}
	if b.Sequence == 1 {
		if b.PreviousSha256 == nil {
			return "healthy"
		}
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	if prev == nil || b.PreviousSha256 == nil || *b.PreviousSha256 != prevHash || prev.IntervalEnd != b.IntervalStart {
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	if prev.ObserverSessionID != b.ObserverSessionID || prev.ConfigSha256 != b.ConfigSha256 || prev.BuildSha256 != b.BuildSha256 || prev.CaptureScopeID != b.CaptureScopeID {
		return "HEALTH_IDENTITY_CHANGED"
	}
	if !reflect.DeepEqual(prev.CounterEnd, b.CounterStart) {
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	return "healthy"
}

func statuses(t *testing.T, ws []Window) []string {
	t.Helper()
	var out []string
	var prevHash string
	for i := range ws {
		// 经 JSON 往返模拟服务端接收，再以规范化摘要串链。
		b, _ := json.Marshal(ws[i])
		var got Window
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		var prev *Window
		if i > 0 {
			prev = &ws[i-1]
		}
		end, _ := time.Parse(time.RFC3339Nano, got.IntervalEnd)
		out = append(out, verify(&got, prev, prevHash, end.Add(time.Second)))
		prevHash, _ = jcs.SHA256(got)
	}
	return out
}

func TestContinuousHealthyChain(t *testing.T) {
	var ws []Window
	o := observer(t, &ws)
	for i := 0; i <= 120; i++ {
		if err := o.Observe(hostguard.LiveSample{At: t0.Add(time.Duration(i) * 100 * time.Millisecond), PacketsSeen: uint64(i * 7), DropsKnown: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Finish(hostguard.LiveSample{At: t0.Add(12050 * time.Millisecond), PacketsSeen: 900, DropsKnown: true}); err != nil {
		t.Fatal(err)
	}
	if len(ws) != 13 {
		t.Fatalf("窗口数 %d", len(ws))
	}
	for i, s := range statuses(t, ws) {
		if s != "healthy" {
			t.Fatalf("第 %d 个窗口 %s", i, s)
		}
		if ws[i].Sequence != int64(i+1) || ws[i].ObserverSessionID != o.Session() || ws[i].ClockSkewMs == nil {
			t.Fatal("序号/会话/偏差错误")
		}
	}
	if *ws[12].CounterEnd.PacketsSeen != 900 || ws[12].IntervalEnd != t0.Add(12050*time.Millisecond).Format(time.RFC3339Nano) {
		t.Fatal("结束窗口未覆盖最后样本")
	}
}

func TestGapUnknownDropsAndStallAreNotHealthy(t *testing.T) {
	var ws []Window
	o := observer(t, &ws)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	samples := []hostguard.LiveSample{
		{At: at(0), DropsKnown: true}, {At: at(1000), PacketsSeen: 5, DropsKnown: true},
		{At: at(1500), PacketsSeen: 6, Drops: 2, DropsKnown: true, Gap: true}, {At: at(2000), PacketsSeen: 7, Drops: 2, DropsKnown: true},
		{At: at(3000), PacketsSeen: 8},                    // 内核丢包不可测
		{At: at(15000), PacketsSeen: 9, DropsKnown: true}, // 轮询停顿 12 秒
		{At: at(16000), PacketsSeen: 10, DropsKnown: true, CapacityDrops: 1},
		{At: at(17000), PacketsSeen: 11, DropsKnown: true, CapacityDrops: 1},
	}
	for _, s := range samples {
		if err := o.Observe(s); err != nil {
			t.Fatal(err)
		}
	}
	got := statuses(t, ws)
	want := []string{"healthy", "CAPTURE_GAP", "COUNTER_UNKNOWN", "CAPTURE_GAP", "CAPTURE_GAP", "CAPTURE_GAP", "CAPTURE_DROPS", "healthy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("状态 %v", got)
	}
	for i, w := range ws {
		s, _ := time.Parse(time.RFC3339Nano, w.IntervalStart)
		e, _ := time.Parse(time.RFC3339Nano, w.IntervalEnd)
		if e.Sub(s) > MaxWindow || !s.Before(e) || i > 0 && ws[i-1].IntervalEnd != w.IntervalStart {
			t.Fatalf("窗口 %d 区间错误 %s..%s", i, w.IntervalStart, w.IntervalEnd)
		}
	}
	if ws[2].CounterEnd.KernelDrops != nil || ws[3].CounterEnd.PacketsSeen != nil {
		t.Fatal("未知计数必须为 null")
	}
	if _, err := New(ident(), Options{Window: 6 * time.Second, NewID: func() string { return "00000000-0000-4000-8000-000000000009" }, Emit: func(Window) error { return nil }}); err == nil {
		t.Fatal("超过 5 秒的窗口未拒绝")
	}
}
