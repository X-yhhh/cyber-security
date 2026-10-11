package hostguard

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sync"
	"time"
)

var ErrTarget = errors.New("TARGET_REFERENCE_REJECTED")

// TargetScope 是本机安装时登记的身份，不从网络请求选择。地址/接口变化必须销毁原注册表。
type TargetScope struct {
	AssetID, SensorID, BootID, CaptureScopeID, Environment string
	ExecutorBootID                                         string
	KeyEpoch                                               int
	LocalAddresses                                         []netip.Addr
	CollectorCertSHA256, ExecutorCertSHA256                string
	MaxReferences                                          int
}
type TargetBinding struct {
	AssetID        string  `json:"assetId"`
	SensorID       string  `json:"sensorId"`
	BootID         string  `json:"bootId"`
	CaptureScopeID string  `json:"captureScopeId"`
	Environment    string  `json:"environment"`
	ExecutorBootID string  `json:"executorBootId"`
	PeerKey        string  `json:"peerKey"`
	KeyEpoch       int     `json:"keyEpoch"`
	Direction      string  `json:"direction"`
	Transport      string  `json:"transport"`
	AddressFamily  string  `json:"addressFamily"`
	Scope          string  `json:"scope"`
	ServicePort    *uint16 `json:"servicePort"`
}
type TargetLease struct {
	Ref       string    `json:"targetRef"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type targetEntry struct {
	binding    TargetBinding
	endpoints  Endpoints
	last       time.Time
	lease      TargetLease
	deadline   time.Time
	registered bool
}
type TargetRegistry struct {
	mu        sync.Mutex
	scope     TargetScope
	entries   map[string]targetEntry
	byTarget  map[string]string
	now       func() time.Time
	lastClock time.Time
	invalid   bool
	register  func(TargetBinding, Endpoints, TargetLease) error
}

// NewTargetRegistry 是易失的 P2 原型；进程重启不恢复引用，也不具有防火墙权限。
func NewTargetRegistry(s TargetScope, now func() time.Time) (*TargetRegistry, error) {
	for _, id := range []string{s.AssetID, s.SensorID, s.BootID, s.CaptureScopeID, s.ExecutorBootID} {
		if !uuidPattern.MatchString(id) {
			return nil, ErrTarget
		}
	}
	if s.Environment != "lab" && s.Environment != "authorized" || s.KeyEpoch < 1 || len(s.LocalAddresses) == 0 || now == nil {
		return nil, ErrTarget
	}
	for _, h := range []string{s.CollectorCertSHA256, s.ExecutorCertSHA256} {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, ErrTarget
		}
	}
	if s.CollectorCertSHA256 == s.ExecutorCertSHA256 {
		return nil, ErrTarget
	}
	if s.MaxReferences == 0 {
		s.MaxReferences = 10000
	}
	if s.MaxReferences < 1 {
		return nil, ErrTarget
	}
	s.LocalAddresses = append([]netip.Addr(nil), s.LocalAddresses...)
	return &TargetRegistry{scope: s, entries: map[string]targetEntry{}, byTarget: map[string]string{}, now: now}, nil
}

// NewRegisteredTargetRegistry 供独立可信解析器使用：后台确认后才发布租约。
// 此模式下同一引用的 expiresAt 不变，过期重新签发引用，避免修改已落库绑定的幂等内容。
// 原 NewTargetRegistry 行为保持不变，既有冻结运行不受影响。
func NewRegisteredTargetRegistry(s TargetScope, now func() time.Time, register func(TargetBinding, Endpoints, TargetLease) error) (*TargetRegistry, error) {
	if register == nil {
		return nil, ErrTarget
	}
	r, err := NewTargetRegistry(s, now)
	if err != nil {
		return nil, err
	}
	r.register = register
	return r, nil
}
func Binding(o Observation, executorBoot string) TargetBinding {
	return bindingForScope(o, executorBoot, "peer_service")
}
func bindingForScope(o Observation, executorBoot, targetScope string) TargetBinding {
	b := TargetBinding{AssetID: o.AssetID, SensorID: o.SensorID, BootID: o.BootID, CaptureScopeID: o.CaptureScopeID, Environment: o.Environment, ExecutorBootID: executorBoot, PeerKey: o.PeerKey, KeyEpoch: o.KeyEpoch, Direction: o.Direction, Transport: o.Transport, AddressFamily: o.AddressFamily, Scope: targetScope}
	if targetScope == "peer_service" {
		b.ServicePort = o.ServicePort
	}
	return b
}
func (r *TargetRegistry) valid(b TargetBinding) bool {
	s := r.scope
	_, err := hex.DecodeString(b.PeerKey)
	validScope := b.Scope == "peer_service" && b.ServicePort != nil && *b.ServicePort > 0 || b.Scope == "peer_inbound" && b.ServicePort == nil && b.Direction == "inbound"
	return b.AssetID == s.AssetID && b.SensorID == s.SensorID && b.BootID == s.BootID && b.CaptureScopeID == s.CaptureScopeID && b.Environment == s.Environment && b.ExecutorBootID == s.ExecutorBootID && b.KeyEpoch == s.KeyEpoch && b.Transport == "tcp" && b.AddressFamily == "ipv4" && (b.Direction == "inbound" || b.Direction == "outbound") && validScope && len(b.PeerKey) == 64 && err == nil
}
func (r *TargetRegistry) clock() (time.Time, error) {
	n := r.now()
	if r.invalid || !r.lastClock.IsZero() && n.Before(r.lastClock) {
		r.invalid = true
		clear(r.entries)
		clear(r.byTarget)
		return n, ErrTarget
	}
	r.lastClock = n
	for ref, v := range r.entries {
		if !n.Before(v.deadline) || !n.Before(v.lease.ExpiresAt) {
			delete(r.entries, ref)
			delete(r.byTarget, targetKey(v.binding, v.endpoints))
		}
	}
	return n, nil
}
func targetKey(b TargetBinding, e Endpoints) string {
	raw, _ := json.Marshal(struct {
		B TargetBinding
		E Endpoints
	}{b, e})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (r *TargetRegistry) issue(o Observation, end Endpoints) (TargetLease, error) {
	return r.issueForScope(o, end, "peer_service")
}
func (r *TargetRegistry) issueForScope(o Observation, end Endpoints, targetScope string) (TargetLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := ModelVector(o); err != nil || !o.AsOf.Equal(o.LastPacketAt) {
		return TargetLease{}, ErrTarget
	}
	now, err := r.clock()
	if err != nil {
		return TargetLease{}, err
	}
	b := bindingForScope(o, r.scope.ExecutorBootID, targetScope)
	if !r.valid(b) || o.Quality.Defective() || o.Quality.ClockSkewMs == nil || math.Abs(*o.Quality.ClockSkewMs) > 1000 || o.LastPacketAt.After(now) || !now.Before(o.LastPacketAt.Add(15*time.Second)) {
		return TargetLease{}, ErrTarget
	}
	local := false
	for _, a := range r.scope.LocalAddresses {
		local = local || a == end.Local.Addr()
	}
	if !local || end.Protocol != 6 || !end.Peer.Addr().Is4() || end.Peer.Addr().IsUnspecified() || end.Peer.Addr().IsMulticast() || end.Peer.Addr() == end.Local.Addr() {
		return TargetLease{}, ErrTarget
	}
	if o.ServicePort == nil || b.Direction == "inbound" && *o.ServicePort != end.Local.Port() || b.Direction == "outbound" && *o.ServicePort != end.Peer.Port() {
		return TargetLease{}, ErrTarget
	}
	key := targetKey(b, end)
	ref := r.byTarget[key]
	if ref == "" {
		if len(r.entries) >= r.scope.MaxReferences {
			return TargetLease{}, ErrTarget
		}
		ref = NewID()
	} else if o.LastPacketAt.Before(r.entries[ref].last) {
		return TargetLease{}, ErrTarget
	}
	expires := o.LastPacketAt.Add(15 * time.Second)
	lease := TargetLease{ref, expires}
	if old, ok := r.entries[ref]; ok && r.register != nil {
		lease = old.lease
		if !old.registered {
			if err := r.register(b, end, lease); err != nil {
				return TargetLease{}, ErrTarget
			}
		}
		old.last = o.LastPacketAt
		old.registered = true
		r.entries[ref] = old
		return lease, nil
	}
	r.entries[ref] = targetEntry{binding: b, endpoints: end, last: o.LastPacketAt, lease: lease, deadline: now.Add(expires.Sub(now))}
	r.byTarget[key] = ref
	if r.register != nil {
		if err := r.register(b, end, lease); err != nil {
			return TargetLease{}, ErrTarget
		}
		v := r.entries[ref]
		v.registered = true
		r.entries[ref] = v
	}
	return lease, nil
}
func (r *TargetRegistry) resolve(ref string, b TargetBinding) (Endpoints, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.clock(); err != nil {
		return Endpoints{}, err
	}
	v, ok := r.entries[ref]
	if !ok || r.register != nil && !v.registered || !r.valid(b) || !reflect.DeepEqual(v.binding, b) {
		return Endpoints{}, ErrTarget
	}
	return v.endpoints, nil
}

// resolveLease 为 P5 返回新鲜度上界；旧 resolve 响应保持兼容。
// lastPacketAt 不随解析请求刷新，执行器必须同时核验10秒证据期限与15秒引用期限。
func (r *TargetRegistry) resolveLease(ref string, b TargetBinding) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.clock(); err != nil {
		return nil, err
	}
	v, ok := r.entries[ref]
	if !ok || r.register != nil && !v.registered || !r.valid(b) || !reflect.DeepEqual(v.binding, b) {
		return nil, ErrTarget
	}
	return struct {
		Endpoints    Endpoints `json:"endpoints"`
		ExpiresAt    time.Time `json:"expiresAt"`
		LastPacketAt time.Time `json:"lastPacketAt"`
	}{v.endpoints, v.lease.ExpiresAt, v.last}, nil
}

// Invalidate 在地址、接口或身份变更时立即撤销所有引用；只能创建新 registry 恢复服务。
func (r *TargetRegistry) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invalid = true
	clear(r.entries)
	clear(r.byTarget)
}

// TargetTLS 强制双方证书验证；私钥由调用者从本机受控存储提供，P2 不生成常驻凭据。
func TargetTLS(certificate tls.Certificate, roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
}

// ServeHTTP 仅处理本机 mTLS 的两种固定消息：collector 登记，executor 解析。
// 该 IPC 不实现命令执行；请求体限32KiB、拒绝未知字段，失败不回显地址或证书。
func (r *TargetRegistry) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	deny := func() { http.Error(w, "TARGET_REFERENCE_REJECTED", http.StatusForbidden) }
	a, _, err := net.SplitHostPort(q.RemoteAddr)
	ip := net.ParseIP(a)
	if err != nil || ip == nil || !ip.IsLoopback() || q.Method != "POST" || q.TLS == nil || len(q.TLS.VerifiedChains) == 0 || len(q.TLS.PeerCertificates) == 0 {
		deny()
		return
	}
	h := sha256.Sum256(q.TLS.PeerCertificates[0].Raw)
	fingerprint := hex.EncodeToString(h[:])
	d := json.NewDecoder(http.MaxBytesReader(w, q.Body, 32<<10))
	d.DisallowUnknownFields()
	decode := func(v any) bool {
		if d.Decode(v) != nil {
			return false
		}
		var extra any
		return d.Decode(&extra) == io.EOF
	}
	w.Header().Set("Content-Type", "application/json")
	switch q.URL.Path {
	case "/v1/targets/lease":
		if fingerprint != r.scope.CollectorCertSHA256 {
			deny()
			return
		}
		var v struct {
			Observation Observation `json:"observation"`
			Endpoints   Endpoints   `json:"endpoints"`
			Scope       string      `json:"scope"`
		}
		if !decode(&v) {
			deny()
			return
		}
		if v.Scope == "" {
			v.Scope = "peer_service"
		}
		lease, err := r.issueForScope(v.Observation, v.Endpoints, v.Scope)
		if err != nil {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(lease)
	case "/v1/targets/resolve", "/v1/targets/resolve-lease":
		if fingerprint != r.scope.ExecutorCertSHA256 {
			deny()
			return
		}
		var v struct {
			Ref     string        `json:"targetRef"`
			Binding TargetBinding `json:"binding"`
		}
		if !decode(&v) {
			deny()
			return
		}
		var end any
		if q.URL.Path == "/v1/targets/resolve-lease" {
			end, err = r.resolveLease(v.Ref, v.Binding)
		} else {
			end, err = r.resolve(v.Ref, v.Binding)
		}
		if err != nil {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(end)
	default:
		deny()
	}
}
