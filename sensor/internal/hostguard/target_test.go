package hostguard

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
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestTargetMTLSAndBindingFailures(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-p2-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caBytes)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	certificate := func(n int64) (tls.Certificate, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(der)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(h[:])
	}
	serverCert, _ := certificate(2)
	collector, collectorHash := certificate(3)
	executor, executorHash := certificate(4)
	outsider, _ := certificate(5)
	var rows []Observation
	c := config(&rows)
	e, _ := New(c)
	push(t, e, pkt(0, false, true, false, 1))
	closeEngine(t, e)
	o := rows[0]
	o.Environment = "lab"
	zero := 0.
	o.Quality.ClockSkewMs = &zero
	now := epoch.Add(time.Second)
	scope := TargetScope{AssetID: o.AssetID, SensorID: o.SensorID, BootID: o.BootID, CaptureScopeID: o.CaptureScopeID, Environment: "lab", ExecutorBootID: NewID(), KeyEpoch: 1, LocalAddresses: []netip.Addr{host}, CollectorCertSHA256: collectorHash, ExecutorCertSHA256: executorHash}
	r, err := NewTargetRegistry(scope, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(r)
	s.TLS = TargetTLS(serverCert, roots)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	defer s.Close()
	client := func(cert tls.Certificate) *http.Client {
		return &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}}}
	}
	defer client(collector).CloseIdleConnections()
	post := func(cert tls.Certificate, path string, body any) (int, []byte) {
		b, _ := json.Marshal(body)
		cl := client(cert)
		defer cl.CloseIdleConnections()
		res, err := cl.Post(s.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, data
	}
	end := Endpoints{netip.AddrPortFrom(host, 80), netip.AddrPortFrom(peer, 40000), 6}
	request := map[string]any{"observation": o, "endpoints": end}
	code, data := post(collector, "/v1/targets/lease", request)
	if code != 200 {
		t.Fatal("collector 登记失败")
	}
	var lease TargetLease
	if err = json.Unmarshal(data, &lease); err != nil {
		t.Fatal(err)
	}
	binding := Binding(o, scope.ExecutorBootID)
	resolve := func(b TargetBinding) map[string]any { return map[string]any{"targetRef": lease.Ref, "binding": b} }
	code, _ = post(executor, "/v1/targets/resolve", resolve(binding))
	if code != 200 {
		t.Fatal("executor 无法解析自己的引用")
	}
	for _, cert := range []tls.Certificate{executor, outsider} {
		code, _ = post(cert, "/v1/targets/lease", request)
		if code != 403 {
			t.Fatal("未拒绝错误角色")
		}
	}
	code, _ = post(collector, "/v1/targets/resolve", resolve(binding))
	if code != 403 {
		t.Fatal("collector 越权解析")
	}
	for _, change := range []func(*TargetBinding){func(b *TargetBinding) { b.AssetID = NewID() }, func(b *TargetBinding) { b.BootID = NewID() }, func(b *TargetBinding) { b.CaptureScopeID = NewID() }, func(b *TargetBinding) { b.Environment = "authorized" }, func(b *TargetBinding) { b.ExecutorBootID = NewID() }, func(b *TargetBinding) { b.KeyEpoch++ }, func(b *TargetBinding) { b.Direction = "outbound" }, func(b *TargetBinding) { b.PeerKey = string(bytes.Repeat([]byte("0"), 64)) }, func(b *TargetBinding) { p := uint16(22); b.ServicePort = &p }, func(b *TargetBinding) { b.Scope = "peer_inbound"; b.ServicePort = nil }} {
		b := binding
		change(&b)
		code, _ = post(executor, "/v1/targets/resolve", resolve(b))
		if code != 403 {
			t.Fatal("引用串目标")
		}
	}
	inboundRequest := map[string]any{"observation": o, "endpoints": end, "scope": "peer_inbound"}
	code, data = post(collector, "/v1/targets/lease", inboundRequest)
	if code != 200 || json.Unmarshal(data, &lease) != nil {
		t.Fatal("全入站引用登记失败")
	}
	inbound := bindingForScope(o, scope.ExecutorBootID, "peer_inbound")
	if inbound.ServicePort != nil {
		t.Fatal("全入站引用保留了服务端口")
	}
	code, _ = post(executor, "/v1/targets/resolve-lease", resolve(inbound))
	if code != 200 {
		t.Fatal("全入站引用解析失败")
	}
	code, _ = post(executor, "/v1/targets/resolve-lease", resolve(binding))
	if code != 403 {
		t.Fatal("全入站引用可按单端口解析")
	}
	badScope := inboundRequest
	badScope["scope"] = "peer_everywhere"
	code, _ = post(collector, "/v1/targets/lease", badScope)
	if code != 403 {
		t.Fatal("未知范围仍可登记")
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Second}
	defer cl.CloseIdleConnections()
	if res, err := cl.Post(s.URL+"/v1/targets/resolve", "application/json", bytes.NewReader([]byte("{}"))); err == nil {
		res.Body.Close()
		t.Fatal("未持客户端证书仍连接成功")
	}
	now = epoch.Add(15 * time.Second)
	code, _ = post(executor, "/v1/targets/resolve", resolve(binding))
	if code != 403 {
		t.Fatal("过期引用仍可用")
	}
	// 新进程/地址变化不恢复旧引用；墙钟回退后整个 registry 失效。
	r2, _ := NewTargetRegistry(scope, func() time.Time { return epoch.Add(time.Second) })
	if _, err = r2.resolve(lease.Ref, binding); err == nil {
		t.Fatal("重启串引用")
	}
	now = epoch.Add(2 * time.Second)
	code, _ = post(collector, "/v1/targets/lease", request)
	if code != 403 {
		t.Fatal("回退时钟未 fail closed")
	}
	r2.Invalidate()
	if _, err = r2.issue(o, end); err == nil {
		t.Fatal("地址变更仍可登记")
	}
}
