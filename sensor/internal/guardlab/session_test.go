package guardlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

func testID(n string) string    { return "00000000-0000-4000-8000-0000000000" + n }
func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

type readerStub struct {
	h   Handoff
	err error
}

func (r *readerStub) LabRun(context.Context, string) (json.RawMessage, error) { return raw(r.h), r.err }

type leaseStub struct {
	got   hostguard.Observation
	ep    hostguard.Endpoints
	scope string
	err   error
}

func (l *leaseStub) Lease(_ context.Context, o hostguard.Observation, e hostguard.Endpoints, scope string) (hostguard.TargetLease, error) {
	l.got = o
	l.ep = e
	l.scope = scope
	return hostguard.TargetLease{Ref: testID("19"), ExpiresAt: o.LastPacketAt.Add(15 * time.Second)}, l.err
}

type fixture struct {
	c     Config
	id    Identity
	r     *readerStub
	l     *leaseStub
	m     Manifest
	mp    Mapping
	sc    Scenarios
	local PrivateMapping
	key   ed25519.PrivateKey
	now   time.Time
}

func fixtureFor(t *testing.T) *fixture {
	t.Helper()
	d := t.TempDir()
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &fixture{now: now, r: &readerStub{}, l: &leaseStub{}}
	f.id = Identity{AssetID: testID("01"), SensorID: testID("02"), BootID: testID("03"), CaptureScopeID: testID("04"), BuildSHA256: strings.Repeat("b", 64), KeyEpoch: 1, LocalAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, PeerSecret: []byte(strings.Repeat("s", 32))}
	f.c = Config{RunID: testID("10"), ScenarioID: "normal-1", MappingFile: filepath.Join(d, "mapping.json"), TrustFile: filepath.Join(d, "trust.json"), EventsFile: filepath.Join(d, "events.jsonl")}
	lab := now.Add(10 * time.Second)
	f.m = Manifest{ContractVersion: Version, SessionID: f.c.RunID, AssetID: f.id.AssetID, SensorID: f.id.SensorID, BootID: f.id.BootID, BundleID: testID("05"), AuthorizationID: testID("06"), AuthorizationRevision: 1, Environment: "lab", RunnerIdentity: "synthetic-runner", EvidenceKind: "lab", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), TimeoutSeconds: 3600, ProtocolVersions: map[string]string{"observation": hostguard.Version, "health": "host-guard-capture-health/1.0.0"}, MappingID: testID("07"), MappingSHA256: strings.Repeat("a", 64), ScenarioSHA256: strings.Repeat("c", 64), Provenance: map[string]string{"extractorSha256": strings.Repeat("d", 64)}, Time: Times{SourceStart: source, LabStart: lab, OffsetMicros: lab.Sub(source).Microseconds(), WarmupStart: source, ScoringStart: source, ScoringEnd: source.Add(time.Minute)}, Speed: 1}
	l := LocalEntry{ScenarioID: f.c.ScenarioID, OriginalLocal: f.id.LocalAddresses[0], OriginalPeer: netip.MustParseAddr("192.0.2.1"), CanaryLocal: netip.MustParseAddr("127.0.0.1"), CanaryPeer: netip.MustParseAddr("127.0.0.2"), Direction: "inbound", Transport: "tcp", AddressFamily: "ipv4", Scope: "peer_service", ServicePort: 443}
	l.PeerKey = peerKey(f.id.PeerSecret, f.id, l.CanaryPeer)
	f.mp = Mapping{Version, f.m.MappingID, f.m.SessionID, []Entry{{ScenarioID: l.ScenarioID, TargetBindingID: testID("08"), PeerKey: l.PeerKey, KeyEpoch: 1, CaptureScopeID: f.id.CaptureScopeID, TargetRef: testID("09")}}}
	f.sc = Scenarios{Version, []Scenario{{ScenarioID: l.ScenarioID, Family: "normal", Source: "model", PCAPRef: "synthetic.pcap", PCAPSHA256: strings.Repeat("e", 64), SourceStart: source, SourceEnd: source.Add(30 * time.Second)}}}
	f.c.MappingSHA256 = f.m.MappingSHA256
	f.local = PrivateMapping{ContractVersion: MappingVersion, SessionID: f.m.SessionID, MappingID: f.m.MappingID, MappingSHA256: f.m.MappingSHA256, ScenarioSHA256: f.m.ScenarioSHA256, BuildSHA256: f.id.BuildSHA256, ExtractorSHA256: f.m.Provenance["extractorSha256"], Entries: []LocalEntry{l}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.key = key
	der, _ := x509.MarshalPKIXPublicKey(pub)
	os.WriteFile(f.c.TrustFile, raw(map[string]string{f.m.RunnerIdentity: base64.StdEncoding.EncodeToString(der)}), 0600)
	f.sync(t)
	return f
}
func (f *fixture) sync(t *testing.T) {
	t.Helper()
	f.r.h.Manifest = raw(f.m)
	f.r.h.Mapping = raw(f.mp)
	f.r.h.Scenarios = raw(f.sc)
	digest, _ := jcs.SHA256(f.r.h.Manifest)
	f.c.SessionSHA256 = digest
	f.local.SessionSHA256 = digest
	f.r.h.State = State{ID: f.c.RunID, Runnable: true, EligibilityStatus: "active", EffectiveEligibility: "active", RunStatus: "running", Revision: 1, AssetID: f.id.AssetID, BundleID: f.m.BundleID, SessionSHA256: digest, ValidUntil: f.m.ValidUntil, StartedAt: &f.now, EvidenceKind: "lab"}
	f.sign(t)
}
func (f *fixture) sign(t *testing.T) {
	t.Helper()
	b, _ := jcs.Canonical(f.local)
	signed := map[string]any{"payload": f.local, "keyId": f.m.RunnerIdentity, "algorithm": "Ed25519", "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, b))}
	if e := os.WriteFile(f.c.MappingFile, raw(signed), 0600); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) open(t *testing.T) *Session {
	t.Helper()
	s, e := Open(context.Background(), f.c, f.id, f.r, f.l, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *fixture) observation() hostguard.Emission {
	p := uint16(443)
	skew := 0.0
	at := time.Now().UTC().Add(-time.Millisecond)
	return hostguard.Emission{Observation: hostguard.Observation{AssetID: f.id.AssetID, SensorID: f.id.SensorID, BootID: f.id.BootID, CaptureScopeID: f.id.CaptureScopeID, Environment: "lab", Direction: "inbound", Transport: "tcp", AddressFamily: "ipv4", ServicePort: &p, PeerKey: peerKey(f.id.PeerSecret, f.id, f.local.Entries[0].OriginalPeer), KeyEpoch: 1, LastPacketAt: at, AsOf: at, FirstSeenAt: at.Add(-time.Second), EmittedAt: at, Quality: hostguard.Quality{ClockSkewMs: &skew}, Features: hostguard.Features{ElapsedMs: 1000, BytesInbound: 42}, Contexts: []hostguard.Context{{WindowSeconds: 5, PeerFlowStarts: 2}}}, Endpoints: hostguard.Endpoints{Local: netip.MustParseAddrPort("192.0.2.2:443"), Peer: netip.MustParseAddrPort("192.0.2.1:50000"), Protocol: 6}}
}

func TestAdmissionAndMappingFailClosed(t *testing.T) {
	cases := map[string]func(*fixture){
		"wrong-session":     func(f *fixture) { f.c.SessionSHA256 = strings.Repeat("0", 64) },
		"wrong-asset":       func(f *fixture) { f.id.AssetID = testID("20") },
		"wrong-boot":        func(f *fixture) { f.id.BootID = testID("20") },
		"wrong-build":       func(f *fixture) { f.id.BuildSHA256 = strings.Repeat("0", 64) },
		"revoked":           func(f *fixture) { f.r.h.State.EffectiveEligibility = "revoked" },
		"interrupted":       func(f *fixture) { f.r.h.State.RunStatus = "interrupted" },
		"timed-out":         func(f *fixture) { f.r.h.State.TimedOut = true },
		"expired":           func(f *fixture) { f.now = f.m.ValidUntil },
		"disconnected":      func(f *fixture) { f.r.err = errors.New("private endpoint must not leak") },
		"mapping-digest":    func(f *fixture) { f.local.MappingSHA256 = strings.Repeat("0", 64); f.sign(t) },
		"cross-session-map": func(f *fixture) { f.local.SessionID = testID("20"); f.sign(t) },
		"wrong-signature": func(f *fixture) {
			b, _ := os.ReadFile(f.c.MappingFile)
			b = []byte(strings.Replace(string(b), "127.0.0.2", "127.0.0.3", 1))
			os.WriteFile(f.c.MappingFile, b, 0600)
		},
		"ipv6":         func(f *fixture) { f.local.Entries[0].CanaryPeer = netip.MustParseAddr("::1"); f.sign(t) },
		"mixed-source": func(f *fixture) { f.local.Entries = append(f.local.Entries, f.local.Entries[0]); f.sign(t) },
		"bad-scope":    func(f *fixture) { f.local.Entries[0].Scope = "all"; f.sign(t) },
		"outbound-inbound-scope": func(f *fixture) {
			f.local.Entries[0].Direction = "outbound"
			f.local.Entries[0].Scope = "peer_inbound"
			f.sign(t)
		},
		"wrong-peer-key":         func(f *fixture) { f.local.Entries[0].PeerKey = strings.Repeat("0", 64); f.sign(t) },
		"wrong-epoch":            func(f *fixture) { f.id.KeyEpoch = 2 },
		"config-mapping-digest":  func(f *fixture) { f.c.MappingSHA256 = strings.Repeat("0", 64) },
		"missing-mapping-digest": func(f *fixture) { f.c.MappingSHA256 = "" },
		"session-id-not-run": func(f *fixture) {
			f.m.SessionID = testID("22")
			f.mp.SessionID = f.m.SessionID
			f.local.SessionID = f.m.SessionID
			f.sync(t)
		},
		"unknown-family": func(f *fixture) { f.sc.Scenarios[0].Family = "other"; f.sync(t) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixtureFor(t)
			change(f)
			_, e := Open(context.Background(), f.c, f.id, f.r, f.l, f.now)
			if e == nil {
				t.Fatal("unsafe input accepted")
			}
			if strings.Contains(e.Error(), "private") {
				t.Fatal("private error leaked")
			}
		})
	}
}
func TestRemoteRevocationAndImmutableInputsStopSession(t *testing.T) {
	for _, kind := range []string{"revoke", "mapping", "disconnect"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureFor(t)
			s := f.open(t)
			switch kind {
			case "revoke":
				f.r.h.State.EffectiveEligibility = "revoked"
			case "mapping":
				f.r.h.Mapping = raw(Mapping{})
			case "disconnect":
				f.r.err = errors.New("offline")
			}
			if s.Check(context.Background(), f.now) == nil {
				t.Fatal("session remained runnable")
			}
			f.sync(t)
			f.r.err = nil
			if s.Check(context.Background(), f.now) == nil {
				t.Fatal("failed process resumed")
			}
		})
	}
}
func TestMappedLeasePreservesFeatureAndTime(t *testing.T) {
	f := fixtureFor(t)
	s := f.open(t)
	v := f.observation()
	ref, expires, e := s.Lease(v.Observation, v.Endpoints)
	if e != nil {
		t.Fatal(e)
	}
	if f.l.got.PeerKey != s.Entry.PeerKey || f.l.ep.Peer.Addr() != s.Local.CanaryPeer || f.l.ep.Local.Addr() != s.Local.CanaryLocal {
		t.Fatal("wrong canary association")
	}
	v.Observation.TargetRef = &ref
	v.Observation.TargetExpiresAt = &expires
	o, e := s.MapEmission(v, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(v.Observation.Features, o.Features) || !reflect.DeepEqual(v.Observation.Contexts, o.Contexts) || !o.AsOf.Equal(v.Observation.AsOf) || !o.EmittedAt.Equal(v.Observation.EmittedAt) {
		t.Fatal("features/time changed")
	}
	for _, bad := range []string{"port", "direction", "protocol", "peer", "research"} {
		t.Run(bad, func(t *testing.T) {
			f := fixtureFor(t)
			s := f.open(t)
			v := f.observation()
			switch bad {
			case "port":
				p := uint16(80)
				v.Observation.ServicePort = &p
			case "direction":
				v.Observation.Direction = "outbound"
			case "protocol":
				v.Observation.Transport = "udp"
			case "peer":
				v.Endpoints.Peer = netip.MustParseAddrPort("192.0.2.9:50000")
			case "research":
				v.Observation.Environment = "research"
			}
			if _, _, e := s.Lease(v.Observation, v.Endpoints); e == nil {
				t.Fatal("unsafe association")
			}
		})
	}
}
func TestSpoolBindsSessionBuildMappingAndOffset(t *testing.T) {
	f := fixtureFor(t)
	s := f.open(t)
	dir := t.TempDir()
	if s.BindSpool(dir, true) != nil || s.BindSpool(dir, false) != nil {
		t.Fatal("spool cannot resume")
	}
	s.Offset++ // derived duration is not the bound source of truth
	for _, change := range []func(){func() { s.Config.RunID = testID("21") }, func() { s.mappingSHA = strings.Repeat("0", 64) }, func() { s.Manifest.Time.OffsetMicros++ }, func() { s.identity.BuildSHA256 = strings.Repeat("0", 64) }} {
		change()
		if s.BindSpool(dir, false) == nil {
			t.Fatal("cross identity spool resumed")
		}
	}
	if s.BindSpool(dir, true) == nil {
		t.Fatal("overwrote spool binding")
	}
}
func TestStrictJSONAndPrivateFiles(t *testing.T) {
	for _, text := range []string{`{"a":1,"a":2}`, `{"a":[{"b":1,"b":2}]}`, `{"a":1} {}`, `{"unknown":1}`} {
		var v struct {
			A any `json:"a"`
		}
		if Decode([]byte(text), &v) == nil {
			t.Fatal(text)
		}
	}
	p := filepath.Join(t.TempDir(), "public.json")
	os.WriteFile(p, []byte("{}"), 0644)
	if _, e := ReadPrivate(p); e == nil {
		t.Fatal("world-readable mapping")
	}
}
func TestPreflightRejectsUnregisteredPackets(t *testing.T) {
	for _, bad := range []bool{false, true} {
		f := fixtureFor(t)
		src := f.local.Entries[0].OriginalPeer
		if bad {
			src = netip.MustParseAddr("192.0.2.99")
		}
		frame := synth.Build(synth.Spec{TS: f.m.Time.SourceStart.Add(time.Second), Src: src, Dst: f.id.LocalAddresses[0], SPort: 50000, DPort: 443, Proto: 6, Flags: synth.SYN}, 256)
		path := filepath.Join(t.TempDir(), "synthetic.pcap")
		file, _ := os.Create(path)
		synth.WritePcap(file, 256, []synth.Frame{frame})
		file.Close()
		b, _ := os.ReadFile(path)
		f.sc.Scenarios[0].PCAPSHA256 = SHA256(b)
		f.sync(t)
		s := f.open(t)
		e := s.Preflight(path)
		if (e != nil) != bad {
			t.Fatalf("bad=%v error=%v", bad, e)
		}
	}
}

func TestEventReferencesExcludeWarmupAndUnboundObservations(t *testing.T) {
	f := fixtureFor(t)
	s := f.open(t)
	if e := s.OpenEvents(); e != nil {
		t.Fatal(e)
	}
	at := s.Scenario.SourceStart.Add(s.Offset)
	ref := testID("30")
	expiry := at.Add(15 * time.Second)
	o := hostguard.Observation{ObservationID: testID("31"), AsOf: at, TargetRef: &ref, TargetExpiresAt: &expiry}
	if e := s.Event(o); e != nil {
		t.Fatal(e)
	}
	o.TargetRef = nil
	s.Event(o)
	o.TargetRef = &ref
	o.AsOf = at.Add(-time.Microsecond)
	s.Event(o)
	if e := s.CloseEvents(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(s.Config.EventsFile)
	if e != nil || strings.Count(string(b), "\n") != 1 || !strings.Contains(string(b), o.ObservationID) {
		t.Fatal("ineligible events were exported")
	}
}

// 正常与攻击场景即使经同一可信解析器取得租约，也不能共用同一 targetRef（执行对象）。
func TestLeaseRejectsTargetSharedAcrossScenarios(t *testing.T) {
	for _, anchor := range []bool{false, true} {
		f := fixtureFor(t)
		second := f.local.Entries[0]
		second.ScenarioID = "attack-2"
		second.OriginalPeer = netip.MustParseAddr("192.0.2.3")
		second.CanaryPeer = netip.MustParseAddr("127.0.0.3")
		second.PeerKey = peerKey(f.id.PeerSecret, f.id, second.CanaryPeer)
		f.local.Entries = append(f.local.Entries, second)
		f.mp.Entries = append(f.mp.Entries, Entry{ScenarioID: second.ScenarioID, TargetBindingID: testID("28"), PeerKey: second.PeerKey, KeyEpoch: 1, CaptureScopeID: f.id.CaptureScopeID, TargetRef: testID("29")})
		attack := f.sc.Scenarios[0]
		attack.ScenarioID = second.ScenarioID
		attack.Family = "brute_force"
		f.sc.Scenarios = append(f.sc.Scenarios, attack)
		if anchor {
			// 解析器返回的是另一场景登记的初始锚点：同样视为合并执行对象。
			f.mp.Entries[1].TargetRef = testID("19")
		}
		f.sync(t)
		s := f.open(t)
		v := f.observation()
		_, _, e := s.Lease(v.Observation, v.Endpoints)
		if anchor {
			if !errors.Is(e, ErrLease) {
				t.Fatal("lease reused another scenario's registered target")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = s.SelectScenario(second.ScenarioID); e != nil {
			t.Fatal(e)
		}
		v.Observation.PeerKey = peerKey(f.id.PeerSecret, f.id, second.OriginalPeer)
		v.Endpoints.Peer = netip.AddrPortFrom(second.OriginalPeer, 50000)
		if _, _, e = s.Lease(v.Observation, v.Endpoints); !errors.Is(e, ErrLease) || !errors.Is(s.Error(), ErrLease) {
			t.Fatal("normal and attack shared one execution target")
		}
	}
}
