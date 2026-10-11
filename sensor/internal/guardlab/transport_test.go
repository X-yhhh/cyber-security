package guardlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/guardup/guarduptest"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

func TestStableTokenMatchesExecutorAndIgnoresEphemeralIdentity(t *testing.T) {
	port := uint16(443)
	b := hostguard.TargetBinding{AssetID: testID("01"), Environment: "lab", Direction: "inbound", Transport: "tcp", AddressFamily: "ipv4", Scope: "peer_service", ServicePort: &port}
	e := hostguard.Endpoints{Local: netip.MustParseAddrPort("127.0.0.1:443"), Peer: netip.MustParseAddrPort("127.0.0.2:50000"), Protocol: 6}
	key := []byte("synthetic-budget-key-32-byte-data")
	// 期望值由 Python executor 的 sorted compact JSON/HMAC 算法独立生成。
	want := map[string]string{"peer_service": "a44c35f486d0c8500c8d72cd861a37d096218c497fe45a929a0b3d0654b7bccd", "peer_inbound": "ebf161e5cac0a6cf8feb9532255679b5745b3a3f8f1b51daf80b22f009d7a229"}
	for _, scope := range []string{"peer_service", "peer_inbound"} {
		b.Scope = scope
		if scope == "peer_inbound" {
			b.ServicePort = nil
		}
		old, err := StableToken(key, b, e)
		if err != nil || old != want[scope] {
			t.Fatalf("%s %s %v", scope, old, err)
		}
		b.BootID = testID("23")
		b.ExecutorBootID = testID("24")
		b.KeyEpoch = 7
		b.PeerKey = strings.Repeat("1", 64)
		e.Peer = netip.AddrPortFrom(e.Peer.Addr(), 50001)
		next, _ := StableToken(key, b, e)
		if old != next {
			t.Fatal("new boot/epoch/reference replenished budget")
		}
	}
}

func TestMTLSLeaseRegistrationRetriesOriginalBytesAndKeepsImmutableExpiry(t *testing.T) {
	pki := guarduptest.NewPKI(t)
	f := fixtureFor(t)
	v := f.observation()
	v.Observation.PeerKey = f.local.Entries[0].PeerKey
	v.Endpoints.Local = netip.MustParseAddrPort("127.0.0.1:443")
	v.Endpoints.Peer = netip.MustParseAddrPort("127.0.0.2:50000")
	var mu sync.Mutex
	var bodies [][]byte
	var keys []string
	var registrations []map[string]any
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/machine/executors/"+testID("11")+"/target-bindings" || r.Header.Get("Authorization") != "Bearer "+guarduptest.Token || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "forbidden", 403)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var reg map[string]any
		json.Unmarshal(body, &reg)
		mu.Lock()
		bodies = append(bodies, body)
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		registrations = append(registrations, reg)
		first := len(bodies) == 1
		mu.Unlock()
		if first {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"requestId": testID("50"), "data": map[string]any{"bindingId": reg["bindingId"], "budgetTargetId": testID("51"), "revision": 1}, "error": nil})
	}))
	backend.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pki.Server}, ClientCAs: pki.Pool, ClientAuth: tls.RequireAndVerifyClientCert}
	backend.StartTLS()
	defer backend.Close()
	certPEM, _ := os.ReadFile(pki.CertFile)
	keyPEM, _ := os.ReadFile(pki.KeyFile)
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	sum := sha256.Sum256(pair.Certificate[0])
	now := time.Now().UTC()
	scope := hostguard.TargetScope{AssetID: f.id.AssetID, SensorID: f.id.SensorID, BootID: f.id.BootID, CaptureScopeID: f.id.CaptureScopeID, Environment: "lab", ExecutorBootID: testID("12"), KeyEpoch: 1, LocalAddresses: []netip.Addr{v.Endpoints.Local.Addr()}, CollectorCertSHA256: hex.EncodeToString(sum[:]), ExecutorCertSHA256: strings.Repeat("a", 64)}
	keyPath := filepath.Join(t.TempDir(), "budget-key")
	os.WriteFile(keyPath, []byte("synthetic-budget-key-32-byte-data"), 0600)
	rc := RegistrationConfig{Backend: TLSConfig{backend.URL, pki.CAFile, pki.CertFile, pki.KeyFile}, CredentialFile: pki.CredFile, BudgetKeyFile: keyPath, IdentityFile: filepath.Join(t.TempDir(), "identity.json"), ExecutorID: testID("11"), Allowed: []RegistrationRule{{v.Endpoints.Local.Addr(), v.Endpoints.Peer.Addr(), v.Observation.PeerKey, "inbound", "peer_service", 443}}}
	reg, e := NewRegistrar(rc, scope)
	if e != nil {
		t.Fatal(e)
	}
	registry, e := hostguard.NewRegisteredTargetRegistry(scope, func() time.Time { mu.Lock(); defer mu.Unlock(); return now }, reg.Register)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(registry)
	server.TLS = hostguard.TargetTLS(pki.Server, pki.Pool)
	server.StartTLS()
	defer server.Close()
	c, e := NewTargetClient(TLSConfig{server.URL, pki.CAFile, pki.CertFile, pki.KeyFile})
	if e != nil {
		t.Fatal(e)
	}
	v.Observation.AsOf = now.Add(-time.Second)
	v.Observation.LastPacketAt = v.Observation.AsOf
	v.Observation.FirstSeenAt = v.Observation.AsOf
	// 从契约结构样例补齐模型向量；租约必须通过真实注册表的 ModelVector 检查。
	sample, _ := os.ReadFile("../../../docs/contracts/examples/observation.json")
	var o hostguard.Observation
	json.Unmarshal(sample, &o)
	o.AssetID = v.Observation.AssetID
	o.SensorID = v.Observation.SensorID
	o.BootID = v.Observation.BootID
	o.CaptureScopeID = v.Observation.CaptureScopeID
	o.Environment = "lab"
	o.PeerKey = v.Observation.PeerKey
	o.KeyEpoch = 1
	o.Direction = "inbound"
	o.AsOf = v.Observation.AsOf
	o.LastPacketAt = o.AsOf
	o.FirstSeenAt = o.AsOf.Add(-time.Second)
	o.EmittedAt = now
	first, e := c.Lease(context.Background(), o, v.Endpoints, "peer_service")
	if e != nil {
		t.Fatal(e)
	}
	o.AsOf = o.AsOf.Add(500 * time.Millisecond)
	o.LastPacketAt = o.AsOf
	o.Features.ElapsedMs = 1500
	second, e := c.Lease(context.Background(), o, v.Endpoints, "peer_service")
	if e != nil {
		t.Fatal(e)
	}
	if first != second {
		t.Fatal("registered targetRef expiration changed")
	}
	mu.Lock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || keys[0] != keys[1] {
		t.Fatal("lost response changed retry identity")
	}
	stable := registrations[1]["stableTargetToken"]
	mu.Unlock()
	// 过期后的新引用继续归属同一稳定预算目标。
	mu.Lock()
	now = now.Add(16 * time.Second)
	mu.Unlock()
	o.AsOf = now.Add(-time.Millisecond)
	o.LastPacketAt = o.AsOf
	o.FirstSeenAt = o.AsOf.Add(-time.Second)
	o.EmittedAt = now
	o.Features.ElapsedMs = 1000
	third, e := c.Lease(context.Background(), o, v.Endpoints, "peer_service")
	if e != nil {
		t.Fatal(e)
	}
	if first.Ref == third.Ref {
		t.Fatal("expired lease reused")
	}
	mu.Lock()
	if len(bodies) != 3 || registrations[2]["stableTargetToken"] != stable {
		t.Fatal("lease renewal reset stable budget")
	}
	mu.Unlock()
	bad := v.Endpoints
	bad.Peer = netip.MustParseAddrPort("127.0.0.9:50000")
	if _, e = c.Lease(context.Background(), o, bad, "peer_service"); e == nil {
		t.Fatal("unregistered peer accepted")
	}
	if _, e = NewRegistrar(rc, scope); e != nil {
		t.Fatal("same stable identity not resumable")
	}
	os.WriteFile(keyPath, []byte(strings.Repeat("x", 32)), 0600)
	if _, e = NewRegistrar(rc, scope); e == nil {
		t.Fatal("key change bypassed continuity")
	}
}

func TestTargetClientRejectsRemoteAndRedirect(t *testing.T) {
	pki := guarduptest.NewPKI(t)
	for _, u := range []string{"http://127.0.0.1:99", "https://example.com", "https://127.0.0.1/path", "https://127.0.0.1/?q=1"} {
		if _, e := NewTargetClient(TLSConfig{u, pki.CAFile, pki.CertFile, pki.KeyFile}); e == nil {
			t.Fatal("unsafe target URL accepted")
		}
	}
}
