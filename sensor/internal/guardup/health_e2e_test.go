package guardup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

// eventually 在 5 秒内轮询条件；只用于等待回环替身后端确认，不依赖真实接口。
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时：%s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestHealthChainLoopbackEndToEnd（B5.4/S4）：Go 健康观察器 → 上传器 → 回环 TLS 1.3 mTLS 替身后端。
// 替身在严格模式下按 GuardHealth.accept/verify 的顺序判定：窗口连续、缺口、未知计数、
// 已受理断连与整体断连后的重连、重复证明。样本与接收时钟均为合成值，不打开网卡，不能作为现场健康证明。
func TestHealthChainLoopbackEndToEnd(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	var mu sync.Mutex
	var serverNow time.Time
	setNow := func(v time.Time) { mu.Lock(); serverNow = v; mu.Unlock() }
	f.SetStrictHealth(func() time.Time { mu.Lock(); defer mu.Unlock(); return serverNow })
	// 第 10 个窗口首发“已受理但连接断开”，必须以原键/原字节重发并拿回同一判定。
	f.SetHealthFault(func(seq int64, attempt int) string {
		if seq == 10 && attempt == 1 {
			return "drop"
		}
		return ""
	})
	srv := startBackend(t, p, f)
	c := clientFor(t, p, srv.URL)
	u := uploaderFor(t, c, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- u.Run(ctx) }()
	eventually(t, "首个心跳偏差", func() bool { _, ok := u.Skew(); return ok })

	var emitted []capturehealth.Window
	hb, err := capturehealth.New(capturehealth.Identity{AssetID: assetID, SensorID: sensorID, CaptureScopeID: scopeID, ConfigSha256: configHash, BuildSha256: buildHash},
		capturehealth.Options{Window: time.Second, Skew: u.Skew, NewID: NewUUID, Emit: func(w capturehealth.Window) error {
			emitted = append(emitted, w)
			return u.SubmitHealth(w)
		}})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	steps := []struct {
		sample hostguard.LiveSample
		down   bool
	}{
		{sample: hostguard.LiveSample{At: at(0), DropsKnown: true}},
		{sample: hostguard.LiveSample{At: at(1000), PacketsSeen: 5, DropsKnown: true}},               // W1
		{sample: hostguard.LiveSample{At: at(2000), PacketsSeen: 9, DropsKnown: true}},               // W2
		{sample: hostguard.LiveSample{At: at(2500), PacketsSeen: 10, DropsKnown: true, Gap: true}},   // 采集缺口
		{sample: hostguard.LiveSample{At: at(3000), PacketsSeen: 11, DropsKnown: true}},              // W3 缺口
		{sample: hostguard.LiveSample{At: at(4000), PacketsSeen: 12}},                                // W4 内核丢包未知
		{sample: hostguard.LiveSample{At: at(5000), PacketsSeen: 13, DropsKnown: true}},              // W5 起点未知
		{sample: hostguard.LiveSample{At: at(6000), PacketsSeen: 14, DropsKnown: true}},              // W6 恢复
		{sample: hostguard.LiveSample{At: at(13000), PacketsSeen: 20, DropsKnown: true}},             // 停顿 7 秒：W7/W8
		{sample: hostguard.LiveSample{At: at(14000), PacketsSeen: 21, DropsKnown: true}},             // W9
		{sample: hostguard.LiveSample{At: at(15000), PacketsSeen: 22, DropsKnown: true}},             // W10 已受理断连
		{sample: hostguard.LiveSample{At: at(16000), PacketsSeen: 23, DropsKnown: true}, down: true}, // W11 后端整体不可用
		{sample: hostguard.LiveSample{At: at(17000), PacketsSeen: 24, DropsKnown: true}},             // W12 重连后续链
	}
	for i, s := range steps {
		setNow(s.sample.At.Add(500 * time.Millisecond))
		if s.down {
			f.SetDown(true)
		}
		if err := hb.Observe(s.sample); err != nil {
			t.Fatal(err)
		}
		if s.down {
			time.Sleep(100 * time.Millisecond)
			if got := len(f.HealthStatuses()); got != len(emitted)-1 {
				t.Fatalf("断连期间窗口不应入库: %d/%d", got, len(emitted))
			}
			f.SetDown(false)
		}
		eventually(t, "窗口确认", func() bool { return len(f.HealthStatuses()) == len(emitted) })
		if i == 0 && len(emitted) != 0 {
			t.Fatal("首个样本不应产生窗口")
		}
	}
	want := []string{"healthy", "healthy", "CAPTURE_GAP", "COUNTER_UNKNOWN", "COUNTER_UNKNOWN", "healthy",
		"CAPTURE_GAP", "CAPTURE_GAP", "healthy", "healthy", "healthy", "healthy"}
	if got := f.HealthStatuses(); !reflect.DeepEqual(got, want) {
		t.Fatalf("健康判定 %v", got)
	}
	stored := f.HealthWindows()
	if len(stored) != len(emitted) || len(emitted) != len(want) {
		t.Fatalf("入库窗口 %d、产生 %d：断连重发不得重复入库", len(stored), len(emitted))
	}
	for i, w := range stored {
		if w["sequence"] != float64(i+1) || w["healthWindowId"] != emitted[i].HealthWindowID || w["observerSessionId"] != hb.Session() {
			t.Fatalf("窗口 %d 序号/身份错误", i)
		}
		if i == 0 {
			if w["previousSha256"] != nil {
				t.Fatal("首窗口不应引用前序摘要")
			}
			continue
		}
		prev, _ := jcs.SHA256(emitted[i-1])
		if w["intervalStart"] != stored[i-1]["intervalEnd"] || w["previousSha256"] != prev {
			t.Fatalf("窗口 %d 未首尾相接或摘要链断裂", i)
		}
	}
	// 未知计数为 null，不以 0 冒充。
	if emitted[3].CounterEnd.KernelDrops != nil || emitted[6].CounterEnd.PacketsSeen != nil || stored[3]["counterEnd"].(map[string]any)["kernelDrops"] != nil {
		t.Fatal("未知计数必须为 null")
	}
	if f.HealthAttempts(10) < 2 {
		t.Fatal("已受理断连后没有原键重发")
	}
	if st := u.Stats(); st.HealthSent != len(want) || st.HealthStatuses["healthy"] != 7 || st.HealthStatuses["CAPTURE_GAP"] != 3 || st.HealthStatuses["COUNTER_UNKNOWN"] != 2 || st.Retries == 0 {
		t.Fatalf("健康统计 %+v", st)
	}

	// 重复证明：同一窗口原键原字节重放只拿回原判定，不形成新证明。
	var out struct {
		HealthWindowID     string `json:"healthWindowId"`
		VerificationStatus string `json:"verificationStatus"`
		ContentSha256      string `json:"contentSha256"`
	}
	raw, _ := json.Marshal(emitted[8])
	if err := c.do(context.Background(), http.MethodPost, "health-windows", emitted[8].HealthWindowID, raw, http.StatusOK, &out); err != nil || out.HealthWindowID != emitted[8].HealthWindowID || out.VerificationStatus != "healthy" {
		t.Fatalf("幂等重放失败 %v %+v", err, out)
	}
	if len(f.HealthWindows()) != len(want) {
		t.Fatal("幂等重放新增了窗口")
	}
	// 旧窗口换新 ID 冒充后续序号：摘要链不接续，不能判 healthy。
	stale := emitted[8]
	stale.HealthWindowID = NewUUID()
	stale.Sequence = int64(len(want) + 1)
	raw, _ = json.Marshal(stale)
	if err := c.do(context.Background(), http.MethodPost, "health-windows", stale.HealthWindowID, raw, http.StatusOK, &out); err != nil || out.VerificationStatus != "HEALTH_CHAIN_INCOMPLETE" {
		t.Fatalf("陈旧窗口被当作连续证明 %v %+v", err, out)
	}
	count := len(f.HealthWindows())
	// 同一观察器会话与序号换 ID 重新提交：409，上传器视为不可重试并停止。
	forged := emitted[8]
	forged.HealthWindowID = NewUUID()
	if err := u.SubmitHealth(forged); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runErr:
		var e *Error
		if !errors.As(err, &e) || e.Code != "IDEMPOTENCY_CONFLICT" {
			t.Fatalf("重复证明未被拒绝: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("重复证明未使上传器停止")
	}
	if len(f.HealthWindows()) != count || u.Stats().FatalCode != "IDEMPOTENCY_CONFLICT" {
		t.Fatal("重复证明被入库或未记录稳定错误码")
	}
}
