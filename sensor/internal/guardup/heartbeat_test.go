package guardup

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type heartbeatTransport func(*http.Request) (*http.Response, error)

func (f heartbeatTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// 健康窗口积压时模拟每次上传耗时 6 秒；控制面的 10 秒存活期限内仍须收到心跳。
// 使用合成时钟和回环 mTLS 后端，不打开网卡，也不实际等待 24 秒。
func TestHeartbeatRemainsFreshWhileHealthWindowsQueue(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	srv := startBackend(t, p, f)
	c := clientFor(t, p, srv.URL)
	u := uploaderFor(t, c, t.TempDir())
	start := time.Now()
	var seconds, lastHeartbeat atomic.Int64
	var stale atomic.Bool
	u.o.Now = func() time.Time { return start.Add(time.Duration(seconds.Load()) * time.Second) }
	transport := c.http.Transport
	c.http.Transport = heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		health := strings.HasSuffix(r.URL.Path, "/health-windows")
		if strings.HasSuffix(r.URL.Path, "/heartbeats") {
			lastHeartbeat.Store(seconds.Load())
		} else if health && seconds.Load()-lastHeartbeat.Load() > 10 {
			stale.Store(true)
		}
		response, err := transport.RoundTrip(r)
		if health && err == nil && response.StatusCode == http.StatusOK {
			seconds.Add(6)
		}
		return response, err
	})
	hb, err := capturehealth.New(capturehealth.Identity{AssetID: assetID, SensorID: sensorID, CaptureScopeID: scopeID, ConfigSha256: configHash, BuildSha256: buildHash},
		capturehealth.Options{Window: time.Second, Skew: func() (int64, bool) { return 0, true }, NewID: NewUUID, Emit: u.SubmitHealth})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 4; i++ {
		if err := hb.Observe(hostguard.LiveSample{At: start.Add(time.Duration(i) * time.Second), PacketsSeen: uint64(i), DropsKnown: true}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	eventually(t, "连续窗口上传", func() bool { return u.Stats().HealthSent == 4 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if stale.Load() || f.Heartbeats() < 4 {
		t.Fatalf("健康上传期间心跳已陈旧或未按期发送：stale=%v, heartbeats=%d", stale.Load(), f.Heartbeats())
	}
}
