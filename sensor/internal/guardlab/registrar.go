package guardlab

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

// RegistrationConfig 仅由独立 guardtargets 进程读取，绝不能放进 sensor 的配置。
// 对应机器身份只需 machine.target.bind；此组件无命令领取、执行或预算清零入口。
type RegistrationConfig struct {
	Backend        TLSConfig          `json:"backend"`
	CredentialFile string             `json:"credentialFile"`
	BudgetKeyFile  string             `json:"budgetKeyFile"`
	IdentityFile   string             `json:"identityFile"`
	ExecutorID     string             `json:"executorId"`
	Allowed        []RegistrationRule `json:"allowed"`
}

// RegistrationRule 是可信安装者登记的 canary 白名单；不接受 collector 自选任意对端。
type RegistrationRule struct {
	Local       netip.Addr `json:"local"`
	Peer        netip.Addr `json:"peer"`
	PeerKey     string     `json:"peerKey"`
	Direction   string     `json:"direction"`
	Scope       string     `json:"scope"`
	ServicePort uint16     `json:"servicePort"`
}
type Registrar struct {
	config    RegistrationConfig
	scope     hostguard.TargetScope
	key       []byte
	token     string
	transport *transport
}

// NewRegistrar 绑定稳定预算密钥身份；重启/换 boot 不换密钥，换密钥不能复用同一账本。
func NewRegistrar(c RegistrationConfig, s hostguard.TargetScope) (*Registrar, error) {
	if !uuid.MatchString(c.ExecutorID) || !filepath.IsAbs(c.IdentityFile) || len(c.Allowed) == 0 || s.Environment == "research" {
		return nil, ErrAdmission
	}
	for _, v := range c.Allowed {
		if !validAddr(v.Local) || !v.Local.Is4() || !validAddr(v.Peer) || !v.Peer.Is4() || v.Local == v.Peer || !hash.MatchString(v.PeerKey) || (v.ServicePort == 0 && v.Scope != "peer_inbound") || (v.Direction != "inbound" && v.Direction != "outbound") || (v.Scope != "peer_service" && v.Scope != "peer_inbound") || v.Scope == "peer_inbound" && v.Direction != "inbound" {
			return nil, ErrAdmission
		}
	}
	k, e := ReadPrivate(c.BudgetKeyFile)
	if e != nil || len(k) < 32 {
		return nil, ErrAdmission
	}
	token, e := ReadPrivate(c.CredentialFile)
	if e != nil {
		return nil, e
	}
	tok := strings.TrimSpace(string(token))
	if !strings.HasPrefix(tok, "mch_") || strings.ContainsAny(tok, "\r\n ") {
		return nil, ErrAdmission
	}
	t, e := newTransport(c.Backend, false)
	if e != nil {
		return nil, e
	}
	identity, _ := json.Marshal(struct{ Version, Asset, Environment, Executor, KeySHA string }{"guard-target-registrar/1", s.AssetID, s.Environment, c.ExecutorID, SHA256(k)})
	if old, e := ReadPrivate(c.IdentityFile); e == nil {
		if string(old) != string(identity) {
			return nil, ErrContinuity
		}
	} else {
		f, e := os.OpenFile(c.IdentityFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, ErrContinuity
		}
		_, e = f.Write(identity)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return nil, ErrContinuity
		}
	}
	return &Registrar{c, s, k, tok, t}, nil
}

func (r *Registrar) allowed(b hostguard.TargetBinding, ep hostguard.Endpoints) bool {
	for _, v := range r.config.Allowed {
		p := ep.Local.Port()
		if b.Direction == "outbound" {
			p = ep.Peer.Port()
		}
		if v.Local == ep.Local.Addr() && v.Peer == ep.Peer.Addr() && v.PeerKey == b.PeerKey && v.Direction == b.Direction && v.Scope == b.Scope && (v.ServicePort == p || v.Scope == "peer_inbound") {
			return true
		}
	}
	return false
}

// StableToken 与 executor.Engine.stable_target 的 JCS/HMAC 完全一致，忽略 boot、keyEpoch 和短期引用。
func StableToken(key []byte, b hostguard.TargetBinding, ep hostguard.Endpoints) (string, error) {
	v := map[string]any{"assetId": b.AssetID, "environment": b.Environment, "peer": ep.Peer.Addr().String(), "direction": b.Direction, "transport": "tcp", "servicePort": b.ServicePort, "addressFamily": "ipv4"}
	if b.Scope == "peer_inbound" {
		v["scope"] = "peer_inbound"
	}
	raw, e := jcs.Canonical(v)
	if e != nil {
		return "", ErrLease
	}
	h := hmac.New(sha256.New, key)
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func bindingID(ref string) string {
	h := sha256.Sum256([]byte("guard-target-binding/1:" + ref))
	h[6] = (h[6] & 15) | 64
	h[8] = (h[8] & 63) | 128
	s := hex.EncodeToString(h[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// Register 是 registry 的可信提交回调。只有后台确认稳定目标后，collector 才拿到可用引用。
// payload/Idempotency-Key 对同一短期引用固定，响应丢失不会创建新预算身份。
func (r *Registrar) Register(b hostguard.TargetBinding, ep hostguard.Endpoints, l hostguard.TargetLease) error {
	if !r.allowed(b, ep) || b.AssetID != r.scope.AssetID || b.SensorID != r.scope.SensorID || b.BootID != r.scope.BootID || b.ExecutorBootID != r.scope.ExecutorBootID {
		return ErrLease
	}
	token, e := StableToken(r.key, b, ep)
	if e != nil {
		return e
	}
	scopeDigest, e := jcs.SHA256(map[string]any{"stableTargetToken": token})
	if e != nil {
		return ErrLease
	}
	key := bindingID(l.Ref)
	body := map[string]any{"bindingId": key, "executorBootId": b.ExecutorBootID, "sensorId": b.SensorID, "collectorBootId": b.BootID, "captureScopeId": b.CaptureScopeID, "targetRef": l.Ref, "peerKey": b.PeerKey, "keyEpoch": b.KeyEpoch, "direction": b.Direction, "transport": b.Transport, "scope": b.Scope, "servicePort": b.ServicePort, "addressFamily": b.AddressFamily, "stableTargetToken": token, "scopeDigest": scopeDigest, "expiresAt": l.ExpiresAt}
	raw, e := json.Marshal(body)
	if e != nil {
		return ErrLease
	}
	var response struct {
		RequestID string `json:"requestId"`
		Data      struct {
			BindingID      string `json:"bindingId"`
			BudgetTargetID string `json:"budgetTargetId"`
			Revision       int    `json:"revision"`
		} `json:"data"`
		Error json.RawMessage `json:"error"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e = r.transport.post(ctx, "/api/v2/machine/executors/"+r.config.ExecutorID+"/target-bindings", key, r.token, raw, &response); e != nil {
		return ErrLease
	}
	if response.RequestID == "" || response.Data.BindingID != key || !uuid.MatchString(response.Data.BudgetTargetID) || response.Data.Revision < 1 || len(response.Error) > 0 && string(response.Error) != "null" {
		return ErrLease
	}
	return nil
}
