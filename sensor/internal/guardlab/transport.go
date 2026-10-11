package guardlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// TLSConfig 不接受 URL 路径、代理、重定向或系统凭据隐式回退。
type TLSConfig struct {
	BaseURL         string `json:"baseUrl"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}
type transport struct {
	base *url.URL
	http *http.Client
}

func newTransport(c TLSConfig, local bool) (*transport, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrAdmission
	}
	if local {
		a, e := netip.ParseAddr(u.Hostname())
		if e != nil || !a.IsLoopback() {
			return nil, ErrAdmission
		}
	}
	ca, e := ReadPrivate(c.CAFile)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrAdmission
	}
	cert, e := ReadPrivate(c.CertificateFile)
	if e != nil {
		return nil, e
	}
	key, e := ReadPrivate(c.KeyFile)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, ErrAdmission
	}
	h := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &transport{u, h}, nil
}

var errTransport = errors.New("LAB_TRANSPORT_UNAVAILABLE")

func (t *transport) post(ctx context.Context, path, key, token string, body []byte, out any) error {
	// 网络断连/5xx 至多重试一次原字节；权限、结构、幂等冲突等 4xx 绝不改键重试。
	for attempt := 0; attempt < 2; attempt++ {
		req, e := http.NewRequestWithContext(ctx, "POST", t.base.JoinPath(path).String(), bytes.NewReader(body))
		if e != nil {
			return ErrAdmission
		}
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		r, e := t.http.Do(req)
		if e != nil {
			if ctx.Err() != nil {
				return errTransport
			}
			continue
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		r.Body.Close()
		if e != nil || len(b) > 1<<20 {
			return errTransport
		}
		if r.StatusCode >= 500 || r.StatusCode == 429 || r.StatusCode == 408 {
			continue
		}
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			return ErrLease
		}
		if Decode(b, out) != nil {
			return ErrLease
		}
		return nil
	}
	return errTransport
}

type TargetClient struct{ t *transport }

func NewTargetClient(c TLSConfig) (*TargetClient, error) {
	t, e := newTransport(c, true)
	return &TargetClient{t}, e
}

// Lease 只调用本机 collector 端点；无 resolve、target-bind 或命令 API。
func (c *TargetClient) Lease(ctx context.Context, o hostguard.Observation, ep hostguard.Endpoints, scope string) (hostguard.TargetLease, error) {
	b, e := json.Marshal(struct {
		Observation hostguard.Observation `json:"observation"`
		Endpoints   hostguard.Endpoints   `json:"endpoints"`
		Scope       string                `json:"scope"`
	}{o, ep, scope})
	if e != nil {
		return hostguard.TargetLease{}, ErrLease
	}
	var l hostguard.TargetLease
	e = c.t.post(ctx, "/v1/targets/lease", "", "", b, &l)
	return l, e
}
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, e := io.Copy(h, r); e != nil {
		return "", ErrMapping
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
