// Package guarduptest 提供只供测试使用的 mTLS PKI 与 v2 机器接入假后端。
//
// 假后端按接口设计模拟：机器证书 + Bearer 双重身份、Idempotency-Key 与 (boot,sequence) 幂等、
// 观察按 observationId 去重且同键不同内容 409、健康窗口按 RFC 8785 摘要串链。不实现推理或决策。
package guarduptest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

// Token 是测试用机器凭据，格式与后端 v2 一致，不对应任何真实客户端。
const Token = "mch_7.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"

// PKI 是测试临时目录中的 CA、服务端与传感器证书；Other* 为非登记 CA 签发的客户端证书。
type PKI struct {
	Dir                                 string
	Pool                                *x509.CertPool
	Server                              tls.Certificate
	CAFile, CertFile, KeyFile, CredFile string
	OtherCertFile, OtherKeyFile         string
}

// NewPKI 生成一次性 ECDSA 证书链，私钥与凭据文件权限为 0600。
func NewPKI(t testing.TB) PKI {
	t.Helper()
	dir := t.TempDir()
	selfSigned := func(serial int64, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, parentKey)
		kb, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	}
	ca, caKey, caDER := selfSigned(1, "test-ca")
	rogue, rogueKey, _ := selfSigned(9, "rogue-ca")
	sc, sk := issue(2, "server", x509.ExtKeyUsageServerAuth, ca, caKey)
	cc, ck := issue(3, "sensor", x509.ExtKeyUsageClientAuth, ca, caKey)
	oc, ok := issue(4, "rogue-sensor", x509.ExtKeyUsageClientAuth, rogue, rogueKey)
	server, err := tls.X509KeyPair(sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	p := PKI{Dir: dir, Pool: pool, Server: server}
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p.CAFile = write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	p.CertFile, p.KeyFile = write("sensor.pem", cc), write("sensor-key.pem", ck)
	p.OtherCertFile, p.OtherKeyFile = write("rogue.pem", oc), write("rogue-key.pem", ok)
	p.CredFile = write("credential", []byte(Token+"\n"))
	return p
}

// Approved 是假后端返回的已批准配置。
type Approved struct {
	SensorID, ConfigID, ConfigHash, CaptureScopeID, AddressFamily, BuildSha256 string
	ContractVersion, ProfileSha256, HealthVersion                              string
	MaxBatchSize                                                               int
}

// Backend 是并发安全的假后端；Fault 可按 (sequence, 第几次尝试) 返回 "503"、"409" 或 "drop"（已受理但断开连接）。
type Backend struct {
	mu          sync.Mutex
	cfg         Approved
	boot        string
	keys        map[string][2]string
	seqs        map[int64]string
	observed    map[string]string
	order       []string
	sequences   []int64
	attempts    map[int64]int
	fault       func(seq int64, attempt int) string
	down        bool
	health      []map[string]any
	healthHash  []string
	statuses    []string
	heartbeats  int
	certSubject string
	// 以下仅在 SetStrictHealth 后启用，模拟 GuardHealth.accept/verify；默认保持原有只查链行为。
	healthNow      func() time.Time
	healthFault    func(seq int64, attempt int) string
	healthAttempts map[int64]int
	healthBySeq    map[string]string
	healthStored   map[string]map[string]any
	healthDigest   map[string]string
	healthStatus   map[string]string
}

func NewBackend(cfg Approved) *Backend {
	return &Backend{cfg: cfg, keys: map[string][2]string{}, seqs: map[int64]string{}, observed: map[string]string{}, attempts: map[int64]int{}}
}

func (f *Backend) SetFault(fn func(seq int64, attempt int) string) {
	f.mu.Lock()
	f.fault = fn
	f.mu.Unlock()
}

// SetStrictHealth 按后端 GuardHealth 规则判定健康窗口：now 为服务端接收时钟；同一
// (observerSessionId, sequence) 或 healthWindowId 的不同内容返回 409，内容相同则幂等返回原判定。
func (f *Backend) SetStrictHealth(now func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthNow = now
	f.healthAttempts = map[int64]int{}
	f.healthBySeq = map[string]string{}
	f.healthStored = map[string]map[string]any{}
	f.healthDigest = map[string]string{}
	f.healthStatus = map[string]string{}
}

// SetHealthFault 按 (窗口 sequence, 第几次尝试) 返回 "503" 或 "drop"（已受理但断开连接），只用于严格模式。
func (f *Backend) SetHealthFault(fn func(seq int64, attempt int) string) {
	f.mu.Lock()
	f.healthFault = fn
	f.mu.Unlock()
}

// HealthAttempts 返回严格模式下某窗口序号的请求次数（含幂等重放）。
func (f *Backend) HealthAttempts(seq int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthAttempts[seq]
}

// HealthWindows 按首次受理顺序返回已入库窗口（JSON 解码后的副本）。
func (f *Backend) HealthWindows() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.health))
	for i, m := range f.health {
		b, _ := json.Marshal(m)
		json.Unmarshal(b, &out[i])
	}
	return out
}

func (f *Backend) SetDown(v bool)         { f.mu.Lock(); f.down = v; f.mu.Unlock() }
func (f *Backend) Attempts(seq int64) int { f.mu.Lock(); defer f.mu.Unlock(); return f.attempts[seq] }
func (f *Backend) CertSubject() string    { f.mu.Lock(); defer f.mu.Unlock(); return f.certSubject }
func (f *Backend) Heartbeats() int        { f.mu.Lock(); defer f.mu.Unlock(); return f.heartbeats }

// Sequences 返回首次受理的批次序号（重试命中幂等不重复记录）。
func (f *Backend) Sequences() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.sequences...)
}

// Observations 按首次入库顺序返回观察原始 JSON。
func (f *Backend) Observations() []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]json.RawMessage, len(f.order))
	for i, id := range f.order {
		out[i] = json.RawMessage(f.observed[id])
	}
	return out
}

// HealthStatuses 返回假后端对每个健康窗口的链校验结果。
func (f *Backend) HealthStatuses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.statuses...)
}

func envelope(data any, code string) []byte {
	if code != "" {
		b, _ := json.Marshal(map[string]any{"requestId": "r", "data": nil, "error": map[string]any{"code": code, "message": "x", "retryable": false}})
		return b
	}
	b, _ := json.Marshal(map[string]any{"requestId": "r", "data": data, "error": nil})
	return b
}

func shaHex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (f *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(status int, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "Bearer "+Token {
		reply(403, envelope(nil, "MACHINE_IDENTITY_REQUIRED"))
		return
	}
	prefix := "/api/v2/machine/sensors/" + f.cfg.SensorID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		reply(404, envelope(nil, "RESOURCE_NOT_FOUND"))
		return
	}
	op := strings.TrimPrefix(r.URL.Path, prefix)
	f.mu.Lock()
	down := f.down
	f.certSubject = r.TLS.PeerCertificates[0].Subject.CommonName
	f.mu.Unlock()
	if down {
		reply(503, envelope(nil, "SERVICE_UNAVAILABLE"))
		return
	}
	if op == "config" && r.Method == http.MethodGet {
		c := f.cfg
		reply(200, envelope(map[string]any{"configId": c.ConfigID, "configHash": c.ConfigHash, "serverTime": time.Now().UTC().Format(time.RFC3339Nano),
			"config": map[string]any{"contractVersion": c.ContractVersion, "profileSha256": c.ProfileSha256, "captureHealthVersion": c.HealthVersion, "interfaceIds": []string{"lo0"},
				"captureScopeId": c.CaptureScopeID, "addressFamily": c.AddressFamily, "buildSha256": c.BuildSha256, "limits": map[string]any{"maxBatchSize": c.MaxBatchSize}}}, ""))
		return
	}
	key := r.Header.Get("Idempotency-Key")
	body, _ := io.ReadAll(r.Body)
	if r.Method != http.MethodPost || !uuidPattern.MatchString(key) {
		reply(400, envelope(nil, "INVALID_REQUEST"))
		return
	}
	var tree any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if d.Decode(&tree) != nil {
		reply(400, envelope(nil, "INVALID_REQUEST"))
		return
	}
	// 观察含浮点特征，受限 JCS 不覆盖；重试发送的是原字节，这里批次直接按原字节摘要。
	reqHash := shaHex(body)
	if op != "observation-batches" {
		canon, err := jcs.Canonical(tree)
		if err != nil {
			reply(400, envelope(nil, "INVALID_JSON"))
			return
		}
		reqHash = shaHex(canon)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	okStatus := 200
	if op == "observation-batches" {
		okStatus = 202
	}
	healthDrop := false
	if op == "health-windows" && f.healthNow != nil {
		// 严格模式按窗口 sequence 统计全部尝试（含幂等重放），并注入 503/已受理断连。
		var seq int64
		if m, ok := tree.(map[string]any); ok {
			if n, ok := m["sequence"].(json.Number); ok {
				seq, _ = n.Int64()
			}
		}
		f.healthAttempts[seq]++
		action := ""
		if f.healthFault != nil {
			action = f.healthFault(seq, f.healthAttempts[seq])
		}
		if action == "503" {
			reply(503, envelope(nil, "SERVICE_UNAVAILABLE"))
			return
		}
		healthDrop = action == "drop"
	}
	if old, ok := f.keys[op+key]; ok {
		if old[0] != reqHash {
			reply(409, envelope(nil, "IDEMPOTENCY_CONFLICT"))
			return
		}
		reply(okStatus, []byte(old[1]))
		return
	}
	var data any
	switch op {
	case "heartbeats":
		var hb struct {
			BootID     string `json:"bootId"`
			ConfigHash string `json:"configHash"`
		}
		json.Unmarshal(body, &hb)
		if hb.ConfigHash != f.cfg.ConfigHash {
			reply(422, envelope(nil, "CONFIG_INACTIVE"))
			return
		}
		f.boot = hb.BootID
		f.heartbeats++
		data = map[string]any{"serverTime": time.Now().UTC().Add(20 * time.Millisecond).Format(time.RFC3339Nano)}
	case "observation-batches":
		var b struct {
			BatchID      string            `json:"batchId"`
			BootID       string            `json:"bootId"`
			Sequence     int64             `json:"sequence"`
			ConfigID     string            `json:"configId"`
			Observations []json.RawMessage `json:"observations"`
		}
		json.Unmarshal(body, &b)
		f.attempts[b.Sequence]++
		action := ""
		if f.fault != nil {
			action = f.fault(b.Sequence, f.attempts[b.Sequence])
		}
		switch {
		case action == "503":
			reply(503, envelope(nil, "SERVICE_UNAVAILABLE"))
			return
		case action == "409":
			reply(409, envelope(nil, "IDEMPOTENCY_CONFLICT"))
			return
		case b.BootID != f.boot:
			reply(422, envelope(nil, "BOOT_ID_MISMATCH"))
			return
		case b.ConfigID != f.cfg.ConfigID || len(b.Observations) == 0 || len(b.Observations) > f.cfg.MaxBatchSize:
			reply(422, envelope(nil, "CONFIG_INACTIVE"))
			return
		}
		if old, ok := f.seqs[b.Sequence]; ok && old != reqHash {
			reply(409, envelope(nil, "IDEMPOTENCY_CONFLICT"))
			return
		}
		f.seqs[b.Sequence] = reqHash
		f.sequences = append(f.sequences, b.Sequence)
		dups := 0
		for _, o := range b.Observations {
			var x struct {
				ID string `json:"observationId"`
			}
			json.Unmarshal(o, &x)
			if h, ok := f.observed[x.ID]; ok {
				if h != string(o) {
					reply(409, envelope(nil, "IDEMPOTENCY_CONFLICT"))
					return
				}
				dups++
				continue
			}
			f.observed[x.ID] = string(o)
			f.order = append(f.order, x.ID)
		}
		resp := envelope(map[string]any{"batchId": b.BatchID, "status": "accepted", "acceptedCount": len(b.Observations) - dups, "duplicateCount": dups, "rejectedCount": 0, "rejections": []any{}}, "")
		f.keys[op+key] = [2]string{reqHash, string(resp)}
		if action == "drop" {
			// 已持久受理但响应在途丢失：客户端只能看到连接中断。
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
		}
		reply(202, resp)
		return
	case "health-windows":
		if f.healthNow != nil {
			f.strictHealth(w, reply, op+key, body, reqHash, healthDrop)
			return
		}
		var m map[string]any
		dd := json.NewDecoder(bytes.NewReader(body))
		dd.UseNumber()
		dd.Decode(&m)
		st := "healthy"
		if n := len(f.health); n > 0 {
			if m["previousSha256"] != f.healthHash[n-1] || m["intervalStart"] != f.health[n-1]["intervalEnd"] {
				st = "HEALTH_CHAIN_INCOMPLETE"
			}
		} else if m["previousSha256"] != nil {
			st = "HEALTH_CHAIN_INCOMPLETE"
		}
		f.health = append(f.health, m)
		f.healthHash = append(f.healthHash, reqHash)
		f.statuses = append(f.statuses, st)
		data = map[string]any{"healthWindowId": m["healthWindowId"], "verificationStatus": st, "contentSha256": reqHash, "serverTime": time.Now().UTC().Format(time.RFC3339Nano)}
	default:
		reply(404, envelope(nil, "RESOURCE_NOT_FOUND"))
		return
	}
	resp := envelope(data, "")
	f.keys[op+key] = [2]string{reqHash, string(resp)}
	reply(okStatus, resp)
}

// Start 以要求并校验客户端证书的 TLS 1.3 启动假后端。
func (f *Backend) Start(t testing.TB, p PKI) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{p.Server}, ClientCAs: p.Pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// strictHealth 在持锁状态下执行，顺序与 GuardHealth.accept 一致：先按 healthWindowId 或
// (observerSessionId, sequence) 查重复——内容相同幂等返回原判定，不同则 409；再按前一序号窗口验证。
func (f *Backend) strictHealth(w http.ResponseWriter, reply func(int, []byte), cacheKey string, body []byte, digest string, drop bool) {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if d.Decode(&m) != nil {
		reply(400, envelope(nil, "INVALID_REQUEST"))
		return
	}
	id, _ := m["healthWindowId"].(string)
	session, _ := m["observerSessionId"].(string)
	number, _ := m["sequence"].(json.Number)
	seq, err := number.Int64()
	if !uuidPattern.MatchString(id) || !uuidPattern.MatchString(session) || err != nil || seq < 1 {
		reply(422, envelope(nil, "INVALID_HEALTH_WINDOW"))
		return
	}
	start, e1 := time.Parse(time.RFC3339Nano, fmt.Sprint(m["intervalStart"]))
	end, e2 := time.Parse(time.RFC3339Nano, fmt.Sprint(m["intervalEnd"]))
	if e1 != nil || e2 != nil || !start.Before(end) || end.Sub(start) > 5*time.Second {
		reply(422, envelope(nil, "INVALID_HEALTH_WINDOW"))
		return
	}
	slot := session + "/" + strconv.FormatInt(seq, 10)
	old := id
	if _, ok := f.healthDigest[old]; !ok {
		old = f.healthBySeq[slot]
	}
	if old != "" {
		if f.healthDigest[old] != digest {
			reply(409, envelope(nil, "IDEMPOTENCY_CONFLICT"))
			return
		}
		reply(200, envelope(map[string]any{"healthWindowId": old, "verificationStatus": f.healthStatus[old], "contentSha256": digest}, ""))
		return
	}
	now := f.healthNow()
	previousID := f.healthBySeq[session+"/"+strconv.FormatInt(seq-1, 10)]
	st := strictVerify(m, f.healthStored[previousID], f.healthDigest[previousID], start, end, seq, now)
	f.health = append(f.health, m)
	f.healthHash = append(f.healthHash, digest)
	f.statuses = append(f.statuses, st)
	f.healthBySeq[slot] = id
	f.healthStored[id] = m
	f.healthDigest[id] = digest
	f.healthStatus[id] = st
	resp := envelope(map[string]any{"healthWindowId": id, "verificationStatus": st, "contentSha256": digest, "serverTime": now.UTC().Format(time.RFC3339Nano)}, "")
	f.keys[cacheKey] = [2]string{digest, string(resp)}
	if drop {
		// 已持久受理但响应在途丢失：客户端只能看到连接中断，须以原字节/原键重试。
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
	}
	reply(200, resp)
}

// strictVerify 移植 GuardHealth.verify 的判定顺序；prev 为空表示前一序号未入库。
func strictVerify(b, prev map[string]any, prevHash string, start, end time.Time, seq int64, now time.Time) string {
	if end.After(now) || now.Sub(end) > 10*time.Second {
		return "HEALTH_DELAY_EXCEEDED"
	}
	skew, ok := b["clockSkewMs"].(json.Number)
	if !ok {
		return "CLOCK_UNTRUSTED"
	}
	if v, err := skew.Float64(); err != nil || math.Abs(v) > 1000 {
		return "CLOCK_UNTRUSTED"
	}
	if gap, _ := b["captureGap"].(bool); gap {
		return "CAPTURE_GAP"
	}
	cs, _ := b["counterStart"].(map[string]any)
	ce, _ := b["counterEnd"].(map[string]any)
	for _, k := range []string{"packetsSeen", "kernelDrops", "capacityDrops"} {
		x, ok1 := cs[k].(json.Number)
		y, ok2 := ce[k].(json.Number)
		if !ok1 || !ok2 {
			return "COUNTER_UNKNOWN"
		}
		a, _ := x.Int64()
		z, _ := y.Int64()
		if z < a || k != "packetsSeen" && z != a {
			return "CAPTURE_DROPS"
		}
	}
	if seq == 1 {
		if b["previousSha256"] == nil {
			return "healthy"
		}
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	if prev == nil || b["previousSha256"] != prevHash {
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	if previousEnd, err := time.Parse(time.RFC3339Nano, fmt.Sprint(prev["intervalEnd"])); err != nil || !previousEnd.Equal(start) {
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	for _, k := range []string{"observerSessionId", "sensorId", "assetId", "captureScopeId", "configSha256", "buildSha256"} {
		if prev[k] != b[k] {
			return "HEALTH_IDENTITY_CHANGED"
		}
	}
	x, _ := json.Marshal(prev["counterEnd"])
	y, _ := json.Marshal(b["counterStart"])
	if !bytes.Equal(x, y) {
		return "HEALTH_CHAIN_INCOMPLETE"
	}
	return "healthy"
}
