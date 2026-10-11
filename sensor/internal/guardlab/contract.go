// Package guardlab 接入已批准的 lab 会话。它只变换身份关联，不改写报文或模型特征，
// 不持有执行器凭据，不领取命令；所有拒绝均返回稳定、不含端点的错误码。
package guardlab

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

const Version = "host-guard-lab/1.0"
const MappingVersion = "host-guard-sensor-mapping/1.0"

var ErrAdmission = errors.New("LAB_ADMISSION_REJECTED")
var ErrMapping = errors.New("LAB_MAPPING_REJECTED")
var ErrLease = errors.New("LAB_TARGET_LEASE_UNAVAILABLE")
var ErrContinuity = errors.New("LAB_SPOOL_BINDING_MISMATCH")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// scenarioName 与 lab 后端 GuardLabContract.scenarios 的 scenarioId 格式一致。
var scenarioName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

// families 与 lab 后端一致：normal 加四个攻击类；其余类别不能借 lab 会话进入执行链。
var families = map[string]bool{"normal": true, "port_scan": true, "brute_force": true, "dos_flood": true, "dos_slow": true}

// Config 是传感器专用配置；所有文件为本机私有文件，不能含执行器机器凭据。
// RunID 即 lab 后端会话 ID（manifest.sessionId，同时是 /lab-validation-runs/{id} 路径参数）；
// SessionSHA256 是 manifest payload 的 JCS 摘要；MappingSHA256 是中央映射文件原字节摘要（manifest.mappingSha256）。
// 三者都由运维显式填写，任一与后台交接不符即拒绝开始，不从服务端响应反向采信。
type Config struct {
	RunID         string        `json:"runId"`
	SessionSHA256 string        `json:"sessionSha256"`
	MappingSHA256 string        `json:"mappingSha256"`
	ScenarioID    string        `json:"scenarioId"`
	MappingFile   string        `json:"mappingFile"`
	TrustFile     string        `json:"trustFile"`
	EventsFile    string        `json:"eventsFile"`
	Targets       TLSConfig     `json:"targets"`
	Inputs        []ReplayInput `json:"inputs,omitempty"`
}

// ReplayInput 按预登记原时间顺序串行回放；重叠场景须独立捕获域，不能串行伪装同时发生。
type ReplayInput struct {
	ScenarioID string `json:"scenarioId"`
	Path       string `json:"path"`
}

// Handoff 逐字段对应 lab 后端 GET /machine/sensors/{sensorId}/lab-validation-runs/{id}。
// RawMessage 保留完整服务端结构，摘要不能由只解析部分字段的结构体重建。
type Handoff struct {
	State     State           `json:"state"`
	Manifest  json.RawMessage `json:"manifest"`
	Mapping   json.RawMessage `json:"mapping"`
	Scenarios json.RawMessage `json:"scenarios"`
}
type State struct {
	Runnable             bool       `json:"runnable"`
	ReasonCodes          []string   `json:"reasonCodes"`
	BlockedReason        *string    `json:"blockedReason"`
	ID                   string     `json:"id"`
	EligibilityStatus    string     `json:"eligibilityStatus"`
	EffectiveEligibility string     `json:"effectiveEligibility"`
	RunStatus            string     `json:"runStatus"`
	TimedOut             bool       `json:"timedOut"`
	Revision             int64      `json:"revision"`
	AssetID              string     `json:"assetId"`
	BundleID             string     `json:"bundleId"`
	SessionSHA256        string     `json:"sessionSha256"`
	ManifestSHA256       string     `json:"manifestSha256"`
	EvidenceKind         string     `json:"evidenceKind"`
	ValidUntil           time.Time  `json:"validUntil"`
	StartedAt            *time.Time `json:"startedAt"`
	EndedAt              *time.Time `json:"endedAt"`
	StopRequestedAt      *time.Time `json:"stopRequestedAt"`
	CleanupStatus        string     `json:"cleanupStatus"`
	ExecutionAuthority   bool       `json:"executionAuthority"`
}
type Times struct {
	SourceStart  time.Time `json:"sourceStart"`
	LabStart     time.Time `json:"labStart"`
	OffsetMicros int64     `json:"offsetMicros"`
	WarmupStart  time.Time `json:"warmupStart"`
	ScoringStart time.Time `json:"scoringStart"`
	ScoringEnd   time.Time `json:"scoringEnd"`
}
type Manifest struct {
	ContractVersion       string                     `json:"contractVersion"`
	SessionID             string                     `json:"sessionId"`
	AssetID               string                     `json:"assetId"`
	BundleID              string                     `json:"bundleId"`
	AuthorizationID       string                     `json:"authorizationId"`
	AuthorizationRevision int64                      `json:"authorizationRevision"`
	Environment           string                     `json:"environment"`
	RunnerIdentity        string                     `json:"runnerIdentity"`
	EvidenceKind          string                     `json:"evidenceKind"`
	ValidFrom             time.Time                  `json:"validFrom"`
	ValidUntil            time.Time                  `json:"validUntil"`
	TimeoutSeconds        int64                      `json:"timeoutSeconds"`
	ProtocolVersions      map[string]string          `json:"protocolVersions"`
	SubjectSHA256         string                     `json:"subjectSha256"`
	EvaluationPlanSHA256  string                     `json:"evaluationPlanSha256"`
	SensorID              string                     `json:"sensorId"`
	BootID                string                     `json:"bootId"`
	ExecutorID            string                     `json:"executorId"`
	ExecutorBootID        string                     `json:"executorBootId"`
	MappingRef            string                     `json:"mappingRef"`
	MappingSHA256         string                     `json:"mappingSha256"`
	MappingID             string                     `json:"mappingId"`
	ScenarioRef           string                     `json:"scenarioRef"`
	ScenarioSHA256        string                     `json:"scenarioSha256"`
	Provenance            map[string]string          `json:"provenance"`
	Proofs                map[string]json.RawMessage `json:"proofs"`
	Time                  Times                      `json:"time"`
	Speed                 int                        `json:"speed"`
}
type Mapping struct {
	ContractVersion string  `json:"contractVersion"`
	MappingID       string  `json:"mappingId"`
	SessionID       string  `json:"sessionId"`
	Entries         []Entry `json:"entries"`
}
type Entry struct {
	ScenarioID      string `json:"scenarioId"`
	TargetBindingID string `json:"targetBindingId"`
	PeerKey         string `json:"peerKey"`
	KeyEpoch        int    `json:"keyEpoch"`
	CaptureScopeID  string `json:"captureScopeId"`
	TargetRef       string `json:"targetRef"`
}
type Scenarios struct {
	ContractVersion string     `json:"contractVersion"`
	Scenarios       []Scenario `json:"scenarios"`
}
type Scenario struct {
	ScenarioID           string    `json:"scenarioId"`
	Family               string    `json:"family"`
	Source               string    `json:"source"`
	RuleID               *string   `json:"ruleId"`
	TrialAutoEligible    bool      `json:"trialAutoEligible"`
	AutoIneligibleReason *string   `json:"autoIneligibleReason"`
	PCAPRef              string    `json:"pcapRef"`
	PCAPSHA256           string    `json:"pcapSha256"`
	SourceStart          time.Time `json:"sourceStart"`
	SourceEnd            time.Time `json:"sourceEnd"`
}

// PrivateMapping 是 runner 另外签名的本机映射，原始端点永不进入中央日志。
// mappingSha256/sessionSha256 锚定中央登记，buildSha256 锚定本次独立构建。
type PrivateMapping struct {
	ContractVersion string       `json:"contractVersion"`
	SessionID       string       `json:"sessionId"`
	SessionSHA256   string       `json:"sessionSha256"`
	MappingID       string       `json:"mappingId"`
	MappingSHA256   string       `json:"mappingSha256"`
	ScenarioSHA256  string       `json:"scenarioSha256"`
	BuildSHA256     string       `json:"buildSha256"`
	ExtractorSHA256 string       `json:"extractorSha256"`
	Entries         []LocalEntry `json:"entries"`
}
type LocalEntry struct {
	ScenarioID    string     `json:"scenarioId"`
	OriginalLocal netip.Addr `json:"originalLocal"`
	OriginalPeer  netip.Addr `json:"originalPeer"`
	CanaryLocal   netip.Addr `json:"canaryLocal"`
	CanaryPeer    netip.Addr `json:"canaryPeer"`
	PeerKey       string     `json:"peerKey"`
	Direction     string     `json:"direction"`
	Transport     string     `json:"transport"`
	AddressFamily string     `json:"addressFamily"`
	Scope         string     `json:"scope"`
	ServicePort   uint16     `json:"servicePort"`
}
type Identity struct {
	AssetID, SensorID, BootID, CaptureScopeID, BuildSHA256 string
	KeyEpoch                                               int
	LocalAddresses                                         []netip.Addr
	PeerSecret                                             []byte
}

// Decode 拒绝未知字段、重复键和尾随 JSON，避免签名解析与实际使用产生歧义。
func Decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 1<<20 || uniqueJSON(raw) != nil {
		return ErrAdmission
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrAdmission
	}
	return nil
}
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrAdmission
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		x, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if x == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return ErrAdmission
				}
				seen[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		} else if x == '[' {
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		} else {
			return ErrAdmission
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrAdmission
	}
	return nil
}
func SHA256(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// ReadPrivate 不跟随符号链接，不接受组/其他用户可访问的文件；错误不回显路径。
func ReadPrivate(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrAdmission
	}
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > 1<<20 {
		return nil, ErrAdmission
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, ErrAdmission
	}
	return b, nil
}
func readMapping(c Config, runner string) (PrivateMapping, string, error) {
	var out PrivateMapping
	raw, e := ReadPrivate(c.MappingFile)
	if e != nil {
		return out, "", e
	}
	var signed struct {
		Payload   json.RawMessage `json:"payload"`
		KeyID     string          `json:"keyId"`
		Algorithm string          `json:"algorithm"`
		Signature string          `json:"signature"`
	}
	if Decode(raw, &signed) != nil || signed.Algorithm != "Ed25519" || signed.KeyID != runner {
		return out, "", ErrMapping
	}
	keys, e := ReadPrivate(c.TrustFile)
	if e != nil {
		return out, "", e
	}
	var trust map[string]string
	if Decode(keys, &trust) != nil {
		return out, "", ErrMapping
	}
	der, e := base64.StdEncoding.DecodeString(trust[runner])
	if e != nil {
		return out, "", ErrMapping
	}
	pub, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return out, "", ErrMapping
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return out, "", ErrMapping
	}
	b, e := jcs.Canonical(signed.Payload)
	if e != nil {
		return out, "", ErrMapping
	}
	// 与 GuardSignatures.sign 一致：签名为无填充 base64url；公钥仍是标准 base64 DER。
	sig, e := base64.RawURLEncoding.DecodeString(signed.Signature)
	if e != nil || !ed25519.Verify(key, b, sig) || Decode(signed.Payload, &out) != nil {
		return out, "", ErrMapping
	}
	return out, SHA256(raw), nil
}
func validAddr(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast() && a.Zone() == ""
}
func peerKey(secret []byte, id Identity, a netip.Addr) string {
	b, _ := json.Marshal([]any{"host-guard-peer-v1", id.AssetID, id.SensorID, id.KeyEpoch, a.String()})
	h := hmac.New(sha256.New, secret)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func offset(t Times) (time.Duration, error) {
	// time.Duration 只容纳约 292 年；先校验再换算，不能溢出成有效时间。
	if t.OffsetMicros > int64((1<<63-1)/1000) || t.OffsetMicros < int64((-1<<63)/1000) {
		return 0, ErrAdmission
	}
	o := time.Duration(t.OffsetMicros) * time.Microsecond
	if t.SourceStart.IsZero() || !t.SourceStart.Add(o).Equal(t.LabStart) || t.WarmupStart.Before(t.SourceStart) || t.ScoringStart.Before(t.WarmupStart) || !t.ScoringEnd.After(t.ScoringStart) {
		return 0, ErrAdmission
	}
	return o, nil
}

// validateHandoff 在每次轮询再次核对资格/时间；可变 revision 不用作不可变输入的替代。
func validateHandoff(c Config, id Identity, h Handoff, now time.Time) (Manifest, Mapping, Scenarios, error) {
	var m Manifest
	var mp Mapping
	var sc Scenarios
	bad := func() (Manifest, Mapping, Scenarios, error) { return m, mp, sc, ErrAdmission }
	if Decode(h.Manifest, &m) != nil || Decode(h.Mapping, &mp) != nil || Decode(h.Scenarios, &sc) != nil {
		return bad()
	}
	d, e := jcs.SHA256(h.Manifest)
	if e != nil || !hash.MatchString(c.SessionSHA256) || d != c.SessionSHA256 || d != h.State.SessionSHA256 || h.State.ID != c.RunID {
		return bad()
	}
	if !h.State.Runnable || len(h.State.ReasonCodes) != 0 || h.State.BlockedReason != nil || h.State.EligibilityStatus != "active" || h.State.EffectiveEligibility != "active" || h.State.RunStatus != "running" || h.State.TimedOut || h.State.StopRequestedAt != nil || h.State.EndedAt != nil || h.State.Revision < 1 || h.State.StartedAt == nil {
		return bad()
	}
	// 会话 ID 与映射摘要须等于运维显式配置值：后端 state.id/public_id 即 manifest.sessionId，
	// mappingSha256 为中央映射文件原字节摘要（交接只给 JCS 内容，传感器不能重算原字节，故以显式配置核对）。
	if m.SessionID != c.RunID || !hash.MatchString(c.MappingSHA256) || m.MappingSHA256 != c.MappingSHA256 {
		return bad()
	}
	if m.ContractVersion != Version || m.Environment != "lab" || m.EvidenceKind != "lab" || m.Speed != 1 || !uuid.MatchString(m.SessionID) || m.AssetID != id.AssetID || m.SensorID != id.SensorID || m.BootID != id.BootID || h.State.AssetID != m.AssetID || h.State.BundleID != m.BundleID || h.State.EvidenceKind != m.EvidenceKind || !h.State.ValidUntil.Equal(m.ValidUntil) {
		return bad()
	}
	if now.Before(m.ValidFrom) || !now.Before(m.ValidUntil) || m.TimeoutSeconds < 10 || m.TimeoutSeconds > 86400 || !m.ValidUntil.After(m.ValidFrom) {
		return bad()
	}
	if m.ProtocolVersions["observation"] != hostguard.Version || m.ProtocolVersions["health"] != "host-guard-capture-health/1.0.0" {
		return bad()
	}
	o, e := offset(m.Time)
	if e != nil || m.Time.WarmupStart.Add(o).Before(m.ValidFrom) || !m.Time.ScoringEnd.Add(o).Before(m.ValidUntil) {
		return bad()
	}
	if mp.ContractVersion != Version || sc.ContractVersion != Version || mp.SessionID != m.SessionID || mp.MappingID != m.MappingID || len(mp.Entries) == 0 || len(mp.Entries) != len(sc.Scenarios) || len(mp.Entries) > 64 {
		return bad()
	}
	seen, refs, peers := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range mp.Entries {
		if seen[v.ScenarioID] || refs[v.TargetRef] || peers[v.PeerKey] || !uuid.MatchString(v.TargetRef) || !uuid.MatchString(v.TargetBindingID) || !uuid.MatchString(v.CaptureScopeID) || !hash.MatchString(v.PeerKey) || v.KeyEpoch < 1 {
			return bad()
		}
		seen[v.ScenarioID] = true
		refs[v.TargetRef] = true
		peers[v.PeerKey] = true
	}
	seen = map[string]bool{}
	for _, s := range sc.Scenarios {
		if seen[s.ScenarioID] || !scenarioName.MatchString(s.ScenarioID) || !families[s.Family] || s.Source != "model" && s.Source != "rule" || !refsFor(mp, s.ScenarioID) || !hash.MatchString(s.PCAPSHA256) || s.SourceStart.Before(m.Time.ScoringStart) || s.SourceEnd.After(m.Time.ScoringEnd) || !s.SourceEnd.After(s.SourceStart) {
			return bad()
		}
		seen[s.ScenarioID] = true
	}
	return m, mp, sc, nil
}
func refsFor(m Mapping, name string) bool {
	for _, v := range m.Entries {
		if v.ScenarioID == name {
			return true
		}
	}
	return false
}
func sameInput(a, b Handoff) bool {
	for _, pair := range [][2]json.RawMessage{{a.Manifest, b.Manifest}, {a.Mapping, b.Mapping}, {a.Scenarios, b.Scenarios}} {
		x, e := jcs.Canonical(pair[0])
		y, f := jcs.Canonical(pair[1])
		if e != nil || f != nil || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}
