package guardlab

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type Reader interface {
	LabRun(context.Context, string) (json.RawMessage, error)
}
type Leaser interface {
	Lease(context.Context, hostguard.Observation, hostguard.Endpoints, string) (hostguard.TargetLease, error)
}

// Session 的不可变输入在启动时冻结，周期只读复核；断连、撤销或变更都停止，恢复不重新计时。
type Session struct {
	Config     Config
	Manifest   Manifest
	Scenario   Scenario
	Entry      Entry
	Local      LocalEntry
	Offset     time.Duration
	identity   Identity
	handoff    Handoff
	reader     Reader
	lease      Leaser
	mappingSHA string
	mu         sync.Mutex
	failure    error
	events     *os.File
	locals     []LocalEntry
	// entries 为中央映射条目；refs 记录本进程内每个已发放 targetRef 归属的场景。
	// 同一引用不得跨场景复用（尤其 normal 与 attack），否则执行对象被合并。
	entries []Entry
	refs    map[string]string
}

// Open 核验服务端会话、runner 签名、本机构建和 canary 一一映射，不建立网络抓包句柄。
func Open(ctx context.Context, c Config, id Identity, reader Reader, leaser Leaser, now time.Time) (*Session, error) {
	if reader == nil || leaser == nil || !uuid.MatchString(c.RunID) || c.ScenarioID == "" || len(id.PeerSecret) < 32 {
		return nil, ErrAdmission
	}
	raw, e := reader.LabRun(ctx, c.RunID)
	if e != nil {
		return nil, ErrAdmission
	}
	var h Handoff
	if Decode(raw, &h) != nil {
		return nil, ErrAdmission
	}
	m, mp, sc, e := validateHandoff(c, id, h, now)
	if e != nil {
		return nil, e
	}
	local, sha, e := readMapping(c, m.RunnerIdentity)
	if e != nil {
		return nil, e
	}
	if local.ContractVersion != MappingVersion || local.SessionID != m.SessionID || local.SessionSHA256 != c.SessionSHA256 || local.MappingID != m.MappingID || local.MappingSHA256 != m.MappingSHA256 || local.ScenarioSHA256 != m.ScenarioSHA256 || local.BuildSHA256 != id.BuildSHA256 || local.ExtractorSHA256 != m.Provenance["extractorSha256"] || len(local.Entries) != len(mp.Entries) {
		return nil, ErrMapping
	}
	s := &Session{Config: c, Manifest: m, identity: id, handoff: h, reader: reader, lease: leaser, mappingSHA: sha}
	s.locals = local.Entries
	s.entries = mp.Entries
	s.refs = map[string]string{}
	s.Offset, e = offset(m.Time)
	if e != nil {
		return nil, e
	}
	usedOrig, usedCanary, seen := map[netip.Addr]bool{}, map[netip.Addr]bool{}, map[string]bool{}
	for _, l := range local.Entries {
		if seen[l.ScenarioID] || !validAddr(l.OriginalLocal) || !validAddr(l.OriginalPeer) || !validAddr(l.CanaryLocal) || !validAddr(l.CanaryPeer) || l.OriginalLocal == l.OriginalPeer || l.CanaryLocal == l.CanaryPeer || usedCanary[l.CanaryPeer] || usedOrig[l.OriginalPeer] {
			return nil, ErrMapping
		}
		// 同一场景固定一个原始来源；多来源必须拆成不同场景/运行和不同 canary。
		if !l.OriginalLocal.Is4() || !l.OriginalPeer.Is4() || !l.CanaryLocal.Is4() || !l.CanaryPeer.Is4() || l.AddressFamily != "ipv4" || l.Transport != "tcp" || l.ServicePort == 0 || (l.Direction != "inbound" && l.Direction != "outbound") || (l.Scope != "peer_service" && l.Scope != "peer_inbound") || l.Scope == "peer_inbound" && l.Direction != "inbound" {
			return nil, ErrMapping
		}
		found := false
		for _, v := range mp.Entries {
			if v.ScenarioID == l.ScenarioID {
				found = true
				if v.PeerKey != l.PeerKey || v.PeerKey != peerKey(id.PeerSecret, id, l.CanaryPeer) || v.KeyEpoch != id.KeyEpoch || v.CaptureScopeID != id.CaptureScopeID {
					return nil, ErrMapping
				}
				if l.ScenarioID == c.ScenarioID {
					s.Entry = v
					s.Local = l
				}
			}
		}
		if !found {
			return nil, ErrMapping
		}
		seen[l.ScenarioID] = true
		usedOrig[l.OriginalPeer] = true
		usedCanary[l.CanaryPeer] = true
	}
	for _, v := range sc.Scenarios {
		if v.ScenarioID == c.ScenarioID {
			s.Scenario = v
		}
	}
	if s.Entry.ScenarioID == "" || s.Scenario.ScenarioID == "" {
		return nil, ErrMapping
	}
	if e = s.SelectScenario(c.ScenarioID); e != nil {
		return nil, e
	}
	return s, nil
}

// SelectScenario 只选择本次不可变会话中已登记的场景，不更换 boot、offset 或上传队列。
// 调用方须在上一个引擎关闭后串行调用。
func (s *Session) SelectScenario(name string) error {
	var mp Mapping
	var sc Scenarios
	if Decode(s.handoff.Mapping, &mp) != nil || Decode(s.handoff.Scenarios, &sc) != nil {
		return ErrMapping
	}
	var local LocalEntry
	var entry Entry
	var scenario Scenario
	for _, v := range s.locals {
		if v.ScenarioID == name {
			local = v
		}
	}
	for _, v := range mp.Entries {
		if v.ScenarioID == name {
			entry = v
		}
	}
	for _, v := range sc.Scenarios {
		if v.ScenarioID == name {
			scenario = v
		}
	}
	found := false
	for _, a := range s.identity.LocalAddresses {
		found = found || a == local.OriginalLocal
	}
	if !found || entry.ScenarioID == "" || scenario.ScenarioID == "" {
		return ErrMapping
	}
	s.Local, s.Entry, s.Scenario = local, entry, scenario
	return nil
}

// Check 是运行中/重连前的在线准入检查；失败为粘性，不能靠稍后一个成功响应恢复同一进程。
func (s *Session) Check(ctx context.Context, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	raw, e := s.reader.LabRun(ctx, s.Config.RunID)
	var h Handoff
	if e == nil {
		e = Decode(raw, &h)
	}
	if e == nil {
		_, _, _, e = validateHandoff(s.Config, s.identity, h, now)
	}
	if e == nil && !sameInput(s.handoff, h) {
		e = ErrAdmission
	}
	if e != nil {
		s.failure = ErrAdmission
	}
	return s.failure
}

// Watch 每秒复核一次机器会话；授权期限直接用墙钟检查，不跟随回放的事件时间平移。
func (s *Session) Watch(ctx context.Context, cancel context.CancelFunc) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if s.Check(ctx, now) != nil {
					cancel()
					return
				}
			}
		}
	}()
	return done
}
func (s *Session) Error() error { s.mu.Lock(); defer s.mu.Unlock(); return s.failure }
func (s *Session) fail(e error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure == nil {
		s.failure = e
	}
	return s.failure
}

// Preflight 仅读签名场景登记的 PCAP，拒绝未登记端点、协议、地址族和服务端口。
// 原件摘要在读取前后核对，期间的文件替换或修改使运行失败。
func (s *Session) Preflight(path string) error {
	sha, e := FileSHA256(path)
	if e != nil || sha != s.Scenario.PCAPSHA256 {
		return ErrMapping
	}
	count := 0
	e = hostguard.WalkPCAP(path, func(b []byte, ci gopacket.CaptureInfo, n uint64) error {
		if ci.Timestamp.Before(s.Manifest.Time.WarmupStart) || ci.Timestamp.After(s.Scenario.SourceEnd) {
			return nil
		}
		p, status := hostguard.Parse(b, ci.Length, ci.Timestamp, n, 1500)
		if status != "ok" || p.Proto != 6 || p.Src != s.Local.OriginalLocal && p.Dst != s.Local.OriginalLocal {
			return ErrMapping
		}
		if p.Src == s.Local.OriginalLocal {
			if p.Dst != s.Local.OriginalPeer {
				return ErrMapping
			}
			if s.Local.Direction == "inbound" && p.SPort != s.Local.ServicePort || s.Local.Direction == "outbound" && p.DPort != s.Local.ServicePort {
				return ErrMapping
			}
		} else {
			if p.Src != s.Local.OriginalPeer || s.Local.Direction == "inbound" && p.DPort != s.Local.ServicePort || s.Local.Direction == "outbound" && p.SPort != s.Local.ServicePort {
				return ErrMapping
			}
		}
		count++
		return nil
	})
	if e != nil || count == 0 {
		return ErrMapping
	}
	after, e := FileSHA256(path)
	if e != nil || after != sha {
		return ErrMapping
	}
	return nil
}
func FileSHA256(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", ErrMapping
	}
	defer f.Close()
	return hashReader(f)
}

// Lease 由因果引擎仅在新包到达时调用。只映射关联身份及本机解析用端点，数值特征不变。
func (s *Session) Lease(o hostguard.Observation, end hostguard.Endpoints) (string, time.Time, error) {
	if s.Error() != nil {
		return "", time.Time{}, s.Error()
	}
	mapped, ep, e := s.mapObservation(o, end)
	if e != nil {
		return "", time.Time{}, s.fail(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l, e := s.lease.Lease(ctx, mapped, ep, s.Local.Scope)
	if e != nil || !uuid.MatchString(l.Ref) || !l.ExpiresAt.After(time.Now()) || l.ExpiresAt.After(o.LastPacketAt.Add(15*time.Second)) {
		return "", time.Time{}, s.fail(ErrLease)
	}
	if !s.claimRef(l.Ref) {
		return "", time.Time{}, s.fail(ErrLease)
	}
	return l.Ref, l.ExpiresAt, nil
}

// claimRef 保证一个 targetRef 只属于一个场景：不能是其他场景登记的初始锚点，
// 也不能已发放给其他场景。正常与攻击来源因此不会被并到同一执行对象。
func (s *Session) claimRef(ref string) bool {
	scenario := s.Scenario.ScenarioID
	for _, v := range s.entries {
		if v.TargetRef == ref && v.ScenarioID != scenario {
			return false
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.refs[ref]; ok && owner != scenario {
		return false
	}
	s.refs[ref] = scenario
	return true
}
func (s *Session) mapObservation(o hostguard.Observation, end hostguard.Endpoints) (hostguard.Observation, hostguard.Endpoints, error) {
	if o.Environment != "lab" || o.AssetID != s.identity.AssetID || o.SensorID != s.identity.SensorID || o.BootID != s.identity.BootID || o.CaptureScopeID != s.identity.CaptureScopeID || o.KeyEpoch != s.identity.KeyEpoch || o.Direction != s.Local.Direction || o.Transport != s.Local.Transport || o.AddressFamily != s.Local.AddressFamily || o.ServicePort == nil || *o.ServicePort != s.Local.ServicePort || end.Local.Addr() != s.Local.OriginalLocal || end.Peer.Addr() != s.Local.OriginalPeer || end.Protocol != 6 {
		return o, end, ErrMapping
	}
	if o.PeerKey != peerKey(s.identity.PeerSecret, s.identity, s.Local.OriginalPeer) {
		return o, end, ErrMapping
	}
	o.PeerKey = s.Entry.PeerKey
	end.Local = netip.AddrPortFrom(s.Local.CanaryLocal, end.Local.Port())
	end.Peer = netip.AddrPortFrom(s.Local.CanaryPeer, end.Peer.Port())
	return o, end, nil
}

// MapEmission 保留过期/质量不足的观察供研判，但清空执行引用；新鲜合格观察缺租约则停止。
func (s *Session) MapEmission(v hostguard.Emission, now time.Time) (hostguard.Observation, error) {
	if e := s.Error(); e != nil {
		return v.Observation, e
	}
	o, _, e := s.mapObservation(v.Observation, v.Endpoints)
	if e != nil {
		return o, s.fail(e)
	}
	if o.Quality.Defective() || o.Quality.ClockSkewMs == nil || math.IsNaN(*o.Quality.ClockSkewMs) || math.Abs(*o.Quality.ClockSkewMs) > 1000 || now.Sub(o.LastPacketAt) > 10*time.Second {
		o.TargetRef = nil
		o.TargetExpiresAt = nil
	} else if o.TargetRef == nil || o.TargetExpiresAt == nil || !o.TargetExpiresAt.After(now) {
		return o, s.fail(ErrLease)
	}
	if len(s.Config.Inputs) > 0 {
		o.ObservationID = s.scenarioID(o.ObservationID)
		o.FlowID = s.scenarioID(o.FlowID)
		o.ParentConnectionID = s.scenarioID(o.ParentConnectionID)
	}
	return o, nil
}

// 多场景共享 boot/sequence，为每个场景的原始 ID 加命名空间，避免不同文件的捕获序号碰撞。
func (s *Session) scenarioID(id string) string {
	b, _ := json.Marshal([]string{"guard-lab-scenario-id/1", s.Manifest.SessionID, s.Scenario.ScenarioID, id})
	h := hmac.New(sha256.New, s.identity.PeerSecret)
	h.Write(b)
	x := h.Sum(nil)
	x[6] = (x[6] & 15) | 64
	x[8] = (x[8] & 63) | 128
	v := hex.EncodeToString(x[:16])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}

// BindSpool 在上传 goroutine 启动前冻结会话/映射/场景/程序。drain 不重写、不重新平移旧字节。
func (s *Session) BindSpool(root string, fresh bool) error {
	if !filepath.IsAbs(root) {
		return ErrContinuity
	}
	dir := filepath.Join(root, s.identity.BootID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return ErrContinuity
	}
	b, e := json.Marshal(struct {
		Version, RunID, SessionSHA256, MappingSHA256, ScenarioID, PCAPSHA256, BuildSHA256 string
		OffsetMicros                                                                      int64
		Inputs                                                                            []ReplayInput
	}{"guard-lab-spool/1", s.Config.RunID, s.Config.SessionSHA256, s.mappingSHA, s.Scenario.ScenarioID, s.Scenario.PCAPSHA256, s.identity.BuildSHA256, s.Manifest.Time.OffsetMicros, s.Config.Inputs})
	if e != nil {
		return ErrContinuity
	}
	p := filepath.Join(dir, "lab-binding.json")
	if !fresh {
		old, e := ReadPrivate(p)
		if e != nil || string(old) != string(b) {
			return ErrContinuity
		}
		return nil
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrContinuity
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return ErrContinuity
	}
	if e = f.Sync(); e != nil {
		return ErrContinuity
	}
	d, e := os.Open(dir)
	if e != nil {
		return ErrContinuity
	}
	defer d.Close()
	return d.Sync()
}

// OpenEvents 输出待 runner 登记的 observation 引用。它不调用需要 evaluation.run 的人工 API。
func (s *Session) OpenEvents() error {
	if !filepath.IsAbs(s.Config.EventsFile) {
		return ErrAdmission
	}
	f, e := os.OpenFile(s.Config.EventsFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrAdmission
	}
	s.events = f
	return nil
}
func (s *Session) Event(o hostguard.Observation) error {
	if s.events == nil {
		return ErrAdmission
	}
	// 中央事件只关联评分段的可解析目标。预热/无租约观察仍完整上传，
	// 由后台质量统计保留，不能作为合格评分或执行证据。
	if o.TargetRef == nil || o.TargetExpiresAt == nil || !o.TargetExpiresAt.After(o.AsOf) || o.AsOf.Before(s.Scenario.SourceStart.Add(s.Offset)) || o.AsOf.After(s.Scenario.SourceEnd.Add(s.Offset)) {
		return nil
	}
	e := json.NewEncoder(s.events).Encode(map[string]any{"eventId": o.ObservationID, "scenarioId": s.Scenario.ScenarioID, "kind": "observation", "referenceId": o.ObservationID})
	if e != nil {
		return ErrAdmission
	}
	return nil
}
func (s *Session) CloseEvents() error {
	if s.events == nil {
		return nil
	}
	e := s.events.Sync()
	closeErr := s.events.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func (s *Session) Summary() map[string]any {
	return map[string]any{"runId": s.Config.RunID, "sessionId": s.Manifest.SessionID, "sessionSha256": s.Config.SessionSHA256, "scenarioId": s.Scenario.ScenarioID, "mappingSha256": s.Manifest.MappingSHA256, "localMappingSha256": s.mappingSHA, "sourceStart": s.Manifest.Time.SourceStart, "warmupStart": s.Manifest.Time.WarmupStart, "scoringStart": s.Manifest.Time.ScoringStart, "scoringEnd": s.Manifest.Time.ScoringEnd, "offsetMicros": s.Manifest.Time.OffsetMicros, "evidenceKind": s.Manifest.EvidenceKind, "g3Passed": false}
}
