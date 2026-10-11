package guardup

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardup/guarduptest"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

const (
	sensorID = "00000000-0000-4000-8000-000000000002"
	assetID  = "00000000-0000-4000-8000-000000000001"
	scopeID  = "00000000-0000-4000-8000-000000000004"
	bootID   = "00000000-0000-4000-8000-000000000003"
	configID = "00000000-0000-4000-8000-0000000000c1"
)

var buildHash = strings.Repeat("b", 64)
var configHash = strings.Repeat("c", 64)

type pki = guarduptest.PKI

func newPKI(t *testing.T) pki { return guarduptest.NewPKI(t) }

func approved() guarduptest.Approved {
	return guarduptest.Approved{SensorID: sensorID, ConfigID: configID, ConfigHash: configHash, CaptureScopeID: scopeID, AddressFamily: "ipv4", BuildSha256: buildHash,
		ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256, HealthVersion: capturehealth.Version, MaxBatchSize: 7}
}

func newBackend() *guarduptest.Backend { return guarduptest.NewBackend(approved()) }

func startBackend(t *testing.T, p pki, f *guarduptest.Backend) *httptest.Server { return f.Start(t, p) }

func clientFor(t *testing.T, p pki, url string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{BaseURL: url, SensorID: sensorID, CAFile: p.CAFile, CertificateFile: p.CertFile, KeyFile: p.KeyFile, CredentialFile: p.CredFile, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func uploaderFor(t *testing.T, c *Client, spoolRoot string) *Uploader {
	t.Helper()
	remote, err := c.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRemote(remote, scopeID, "ipv4", buildHash); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSpool(spoolRoot, SpoolMeta{SensorID: sensorID, BootID: bootID, ConfigID: remote.ConfigID, ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256}, remote.Config.Limits.MaxBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(Options{Client: c, Spool: s, Remote: remote, BootID: bootID, Version: "guardlive-test", MaxDelay: 20 * time.Millisecond, Backoff: func(int) time.Duration { return 5 * time.Millisecond }})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func obs(i int) []byte {
	return []byte(fmt.Sprintf(`{"observationId":"00000000-0000-4000-9000-%012d","snapshotIndex":%d}`, i, i))
}

func checkExactlyOnce(t *testing.T, f *guarduptest.Backend, n int) {
	t.Helper()
	if got := len(f.Observations()); got != n {
		t.Fatalf("服务端入库 %d 条，期望 %d（不丢不重）", got, n)
	}
	for i, s := range f.Sequences() {
		if s != int64(i+1) {
			t.Fatalf("批次序号不连续: %v", f.Sequences())
		}
	}
}

func TestUploadExactlyOnceAcrossFaults(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	f.SetFault(func(seq int64, attempt int) string {
		switch {
		case seq%3 == 0 && attempt == 1:
			return "drop"
		case seq%5 == 0 && attempt <= 2:
			return "503"
		}
		return ""
	})
	srv := startBackend(t, p, f)
	u := uploaderFor(t, clientFor(t, p, srv.URL), t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- u.Run(ctx) }()
	n := 0
	hb, err := capturehealth.New(capturehealth.Identity{AssetID: assetID, SensorID: sensorID, CaptureScopeID: scopeID, ConfigSha256: configHash, BuildSha256: buildHash},
		capturehealth.Options{Skew: u.Skew, QueueMax: u.QueueDepth, NewID: NewUUID, Emit: u.SubmitHealth})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 250; i++ {
		if err := u.Submit(obs(i)); err != nil {
			t.Fatal(err)
		}
		n++
		if err := hb.Observe(hostguard.LiveSample{At: start.Add(time.Duration(i) * 50 * time.Millisecond), PacketsSeen: uint64(i), DropsKnown: true}); err != nil {
			t.Fatal(err)
		}
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	if err := u.Drain(dctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	checkExactlyOnce(t, f, n)
	st := u.Stats()
	if st.Accepted != n || st.Duplicates != 0 || st.Retries == 0 || st.PendingBatches != 0 || st.AckedBatches != st.SealedBatches {
		t.Fatalf("统计错误 %+v", st)
	}
	statuses := f.HealthStatuses()
	if f.CertSubject() != "sensor" || len(statuses) == 0 {
		t.Fatal("未经 mTLS 传感器证书或缺少健康窗口")
	}
	for i, s := range statuses {
		if s != "healthy" {
			t.Fatalf("健康窗口 %d 链断裂: %s", i, s)
		}
	}
	if st.HealthSent != len(statuses) || st.HealthStatuses["healthy"] != len(statuses) {
		t.Fatalf("健康统计错误 %+v", st)
	}
}

func TestUploadResumesFromSpoolAfterRestart(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	// 第 2 批首次已受理但响应丢失；之后服务不可用，进程在未确认状态下退出。
	f.SetFault(func(seq int64, attempt int) string {
		if seq == 2 && attempt == 1 {
			return "drop"
		}
		if seq >= 2 {
			return "503"
		}
		return ""
	})
	srv := startBackend(t, p, f)
	root := t.TempDir()
	u1 := uploaderFor(t, clientFor(t, p, srv.URL), root)
	ctx1, cancel1 := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- u1.Run(ctx1) }()
	for i := 0; i < 40; i++ {
		if err := u1.Submit(obs(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := u1.o.Spool.Seal(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := f.Attempts(2); a >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel1()
	<-done
	if _, pending, _, _ := u1.o.Spool.State(); pending == 0 {
		t.Fatal("重启前应有未确认批次")
	}
	// 新进程：同一 spool、服务恢复；第 2 批以原 Idempotency-Key 重发拿回原结果。
	f.SetFault(nil)
	u2 := uploaderFor(t, clientFor(t, p, srv.URL), root)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { done <- u2.Run(ctx2) }()
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	if err := u2.Drain(dctx); err != nil {
		t.Fatal(err)
	}
	checkExactlyOnce(t, f, 40)
	if st := u2.Stats(); st.Duplicates != 0 {
		t.Fatalf("重启后出现重复入库 %+v", st)
	}
}

func TestFatalRejectionStopsUpload(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	f.SetFault(func(seq int64, attempt int) string { return "409" })
	srv := startBackend(t, p, f)
	u := uploaderFor(t, clientFor(t, p, srv.URL), t.TempDir())
	done := make(chan error, 1)
	go func() { done <- u.Run(context.Background()) }()
	for i := 0; i < 7; i++ {
		u.Submit(obs(i))
	}
	select {
	case err := <-done:
		var e *Error
		if !errors.As(err, &e) || e.Code != "IDEMPOTENCY_CONFLICT" {
			t.Fatalf("应以幂等冲突停止: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("致命错误未停止上传")
	}
	if u.Submit(obs(99)) == nil {
		t.Fatal("致命错误后仍接受观察")
	}
	if f.Attempts(1) != 1 {
		t.Fatal("不可重试错误被重试")
	}
}

func TestClientTransportBoundaries(t *testing.T) {
	p := newPKI(t)
	f := newBackend()
	srv := startBackend(t, p, f)
	base := ClientConfig{BaseURL: srv.URL, SensorID: sensorID, CAFile: p.CAFile, CertificateFile: p.CertFile, KeyFile: p.KeyFile, CredentialFile: p.CredFile}
	bad := []func(c *ClientConfig){
		func(c *ClientConfig) { c.BaseURL = strings.Replace(srv.URL, "https", "http", 1) },
		func(c *ClientConfig) { c.BaseURL = srv.URL + "/api" },
		func(c *ClientConfig) { c.SensorID = "7" },
		func(c *ClientConfig) { c.CertificateFile = "" },
		func(c *ClientConfig) { c.KeyFile = "relative.pem" },
	}
	for i, mutate := range bad {
		c := base
		mutate(&c)
		if _, err := NewClient(c); err == nil {
			t.Fatalf("第 %d 个越界配置未拒绝", i)
		}
	}
	loose := filepath.Join(p.Dir, "loose-credential")
	os.WriteFile(loose, []byte(guarduptest.Token), 0o644)
	c := base
	c.CredentialFile = loose
	if _, err := NewClient(c); err == nil {
		t.Fatal("凭据文件权限过宽未拒绝")
	}
	link := filepath.Join(p.Dir, "key-link")
	os.Symlink(p.KeyFile, link)
	c = base
	c.KeyFile = link
	if _, err := NewClient(c); err == nil {
		t.Fatal("符号链接私钥未拒绝")
	}
	os.WriteFile(filepath.Join(p.Dir, "bad-cred"), []byte("Bearer something"), 0o600)
	c = base
	c.CredentialFile = filepath.Join(p.Dir, "bad-cred")
	if _, err := NewClient(c); err == nil {
		t.Fatal("凭据格式未校验")
	}
	// 非登记 CA 签发的客户端证书在 TLS 握手即被拒绝。
	c = base
	c.CertificateFile, c.KeyFile = p.OtherCertFile, p.OtherKeyFile
	rogue, err := NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rogue.Config(context.Background()); err == nil || !Retryable(err) {
		t.Fatalf("未登记客户端证书应在握手失败: %v", err)
	}
	if _, err := clientFor(t, p, srv.URL).Config(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRemoteFailsClosed(t *testing.T) {
	var ok RemoteConfig
	ok.ConfigID, ok.ConfigHash = configID, configHash
	ok.Config.ContractVersion, ok.Config.ProfileSha256, ok.Config.CaptureHealthVersion = hostguard.Version, hostguard.FeatureProfileSHA256, capturehealth.Version
	ok.Config.CaptureScopeID, ok.Config.AddressFamily, ok.Config.BuildSha256 = scopeID, "ipv4", buildHash
	ok.Config.Limits.MaxBatchSize = MaxBatchSize
	if err := VerifyRemote(ok, scopeID, "ipv4", buildHash); err != nil {
		t.Fatal(err)
	}
	for want, mutate := range map[string]func(r *RemoteConfig){
		"CONTRACT_UNSUPPORTED":       func(r *RemoteConfig) { r.Config.ProfileSha256 = strings.Repeat("0", 64) },
		"HEALTH_VERSION_UNSUPPORTED": func(r *RemoteConfig) { r.Config.CaptureHealthVersion = "x" },
		"SCOPE_DENIED":               func(r *RemoteConfig) { r.Config.AddressFamily = "ipv6" },
		"BUILD_NOT_APPROVED":         func(r *RemoteConfig) { r.Config.BuildSha256 = strings.Repeat("d", 64) },
		"CAPACITY_EXCEEDED":          func(r *RemoteConfig) { r.Config.Limits.MaxBatchSize = MaxBatchSize + 1 },
	} {
		r := ok
		mutate(&r)
		if err := VerifyRemote(r, scopeID, "ipv4", buildHash); err == nil || err.Error() != want {
			t.Fatalf("期望 %s，得到 %v", want, err)
		}
	}
}

func TestSpoolIdentityAndOrdering(t *testing.T) {
	root := t.TempDir()
	meta := SpoolMeta{SensorID: sensorID, BootID: bootID, ConfigID: configID, ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256}
	s, err := OpenSpool(root, meta, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err = s.Append(obs(i), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Ack(2, []byte("{}")); err == nil {
		t.Fatal("乱序确认未拒绝")
	}
	seq, _, b, ok, err := s.Next()
	if err != nil || !ok || seq != 1 || b.Sequence != 1 || len(b.Observations) != 2 {
		t.Fatal("首个批次错误")
	}
	if err = s.Ack(1, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	other := meta
	other.ConfigID = "00000000-0000-4000-8000-0000000000c2"
	if _, err = OpenSpool(root, other, 2); err == nil {
		t.Fatal("同一 boot 换配置未拒绝")
	}
	re, err := OpenSpool(root, meta, 2)
	if err != nil {
		t.Fatal(err)
	}
	seq2, _, _, ok, _ := re.Next()
	if !ok || seq2 != 2 {
		t.Fatal("重开后未从首个未确认批次续传")
	}
	if sealed, pending, _, last := re.State(); sealed != 2 || pending != 1 || last != 1 {
		t.Fatalf("重开状态错误 %d %d %d", sealed, pending, last)
	}
	// 内存中未封口的第 5 条只在进程崩溃时丢失；正常退出由 Drain 封口，网络中断不影响已封口批次。
}
