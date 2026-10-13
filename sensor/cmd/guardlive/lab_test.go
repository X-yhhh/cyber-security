package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardlab"
	"github.com/xyh/cyber-security/sensor/internal/guardup/guarduptest"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
	"github.com/xyh/cyber-security/sensor/internal/replaydiff"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// 实际 guardlive 入口经 mTLS 读取会话、申请租约并上传短小的合成 PCAP，随后原字节 drain。
func TestLabCLIUsesRegisteredClockMappingAndSpool(t *testing.T) {
	for _, v := range []struct {
		name                 string
		plan, shared, replay bool
	}{{"single", false, false, false}, {"plan", true, false, false}, {"plan-shared-target", true, true, false}, {"replay-health", true, false, true}} {
		t.Run(v.name, func(t *testing.T) { testLabCLI(t, v.plan, v.shared, v.replay) })
	}
}

// shared=true 时可信解析器替身把 normal 与 attack 映射到同一 targetRef，入口必须拒绝并以稳定错误码失败。
func testLabCLI(t *testing.T, plan, shared, replay bool) {
	dir := t.TempDir()
	pki := guarduptest.NewPKI(t)
	originalLocal := netip.MustParseAddr("192.0.2.2")
	originalPeer := netip.MustParseAddr("192.0.2.1")
	const boot = "00000000-0000-4000-8000-000000000010"
	const runID = "00000000-0000-4000-8000-000000000011"
	const mapID = "00000000-0000-4000-8000-000000000012"
	const targetID = "00000000-0000-4000-8000-000000000013"
	const attackTargetID = "00000000-0000-4000-8000-000000000016"
	keyMaterial := []byte(strings.Repeat("s", 32))
	secretPath := filepath.Join(dir, "secret")
	os.WriteFile(secretPath, keyMaterial, 0600)
	exe, _ := os.Executable()
	build, _ := digest(exe)
	source := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	frames := []synth.Frame{}
	specs := []synth.Spec{
		{TS: source, Src: originalPeer, Dst: originalLocal, SPort: 50000, DPort: 443, Proto: 6, Flags: synth.SYN},
		{TS: source.Add(10 * time.Millisecond), Src: originalLocal, Dst: originalPeer, SPort: 443, DPort: 50000, Proto: 6, Flags: synth.SYN | synth.ACK},
		{TS: source.Add(20 * time.Millisecond), Src: originalPeer, Dst: originalLocal, SPort: 50000, DPort: 443, Proto: 6, Flags: synth.ACK},
		{TS: source.Add(1200 * time.Millisecond), Src: originalPeer, Dst: originalLocal, SPort: 50000, DPort: 443, Proto: 6, Flags: synth.ACK, Payload: 100},
		{TS: source.Add(2 * time.Second), Src: originalLocal, Dst: originalPeer, SPort: 443, DPort: 50000, Proto: 6, Flags: synth.RST | synth.ACK},
	}
	for _, s := range specs {
		frames = append(frames, synth.Build(s, 256))
	}
	pcap := filepath.Join(dir, "synthetic.pcap")
	f, _ := os.Create(pcap)
	synth.WritePcap(f, 256, frames)
	f.Close()
	pcapHash, _ := guardlab.FileSHA256(pcap)
	canary := netip.MustParseAddr("127.0.0.2")
	data, _ := json.Marshal([]any{"host-guard-peer-v1", assetID, sensor, 1, canary.String()})
	mac := hmac.New(sha256.New, keyMaterial)
	mac.Write(data)
	peerKey := hex.EncodeToString(mac.Sum(nil))
	otherPeer := netip.MustParseAddr("192.0.2.3")
	otherCanary := netip.MustParseAddr("127.0.0.3")
	data2, _ := json.Marshal([]any{"host-guard-peer-v1", assetID, sensor, 1, otherCanary.String()})
	mac2 := hmac.New(sha256.New, keyMaterial)
	mac2.Write(data2)
	peerKey2 := hex.EncodeToString(mac2.Sum(nil))
	pcap2 := filepath.Join(dir, "synthetic-2.pcap")
	var frames2 []synth.Frame
	for _, sp := range specs {
		sp.TS = sp.TS.Add(4 * time.Second)
		if sp.Src == originalPeer {
			sp.Src = otherPeer
		}
		if sp.Dst == originalPeer {
			sp.Dst = otherPeer
		}
		frames2 = append(frames2, synth.Build(sp, 256))
	}
	f2, _ := os.Create(pcap2)
	synth.WritePcap(f2, 256, frames2)
	f2.Close()
	pcapHash2, _ := guardlab.FileSHA256(pcap2)

	healthVersion := capturehealth.Version
	if replay {
		healthVersion = capturehealth.ReplayVersion
	}
	backend := guarduptest.NewBackend(guarduptest.Approved{SensorID: sensor, ConfigID: "00000000-0000-4000-8000-000000000014", ConfigHash: strings.Repeat("f", 64), CaptureScopeID: scope, AddressFamily: "ipv4", BuildSha256: build, ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256, HealthVersion: healthVersion, MaxBatchSize: 100})
	var runnable atomic.Bool
	runnable.Store(true)
	var handoff guardlab.Handoff
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/machine/sensors/"+sensor+"/lab-validation-runs/"+runID {
			if r.Header.Get("Authorization") != "Bearer "+guarduptest.Token || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
				http.Error(w, "denied", 403)
				return
			}
			h := handoff
			h.State.Runnable = runnable.Load()
			json.NewEncoder(w).Encode(map[string]any{"requestId": runID, "data": h, "error": nil})
			return
		}
		backend.ServeHTTP(w, r)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pki.Server}, ClientCAs: pki.Pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	targets := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Observation hostguard.Observation `json:"observation"`
			Endpoints   hostguard.Endpoints   `json:"endpoints"`
			Scope       string                `json:"scope"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if r.URL.Path != "/v1/targets/lease" || !(in.Observation.PeerKey == peerKey && in.Endpoints.Peer.Addr() == canary || plan && in.Observation.PeerKey == peerKey2 && in.Endpoints.Peer.Addr() == otherCanary) || in.Scope != "peer_service" {
			http.Error(w, "denied", 403)
			return
		}
		ref := targetID
		if in.Observation.PeerKey == peerKey2 && !shared {
			ref = attackTargetID
		}
		json.NewEncoder(w).Encode(hostguard.TargetLease{Ref: ref, ExpiresAt: in.Observation.LastPacketAt.Add(15 * time.Second)})
	}))
	targets.TLS = server.TLS.Clone()
	targets.StartTLS()
	defer targets.Close()
	start := time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
	offset := start.Sub(source)
	manifest := guardlab.Manifest{ContractVersion: guardlab.Version, SessionID: runID, AssetID: assetID, SensorID: sensor, BootID: boot, BundleID: mapID, Environment: "lab", EvidenceKind: "lab", RunnerIdentity: "test-runner", ValidFrom: start.Add(-time.Minute), ValidUntil: start.Add(time.Minute), TimeoutSeconds: 60, ProtocolVersions: map[string]string{"observation": hostguard.Version, "health": "host-guard-capture-health/1.0.0"}, MappingID: mapID, MappingSHA256: strings.Repeat("a", 64), ScenarioSHA256: strings.Repeat("c", 64), Provenance: map[string]string{"extractorSha256": strings.Repeat("d", 64)}, Time: guardlab.Times{SourceStart: source, LabStart: start, OffsetMicros: offset.Microseconds(), WarmupStart: source, ScoringStart: source, ScoringEnd: source.Add(3 * time.Second)}, Speed: 1}
	if plan {
		manifest.Time.ScoringEnd = source.Add(7 * time.Second)
	}
	if replay {
		manifest.ContractVersion = guardlab.Version11
		manifest.ProtocolVersions["health"] = healthVersion
		manifest.Time.ScenarioOffsets = map[string]int64{"normal-1": offset.Microseconds(), "attack-2": offset.Microseconds()}
	}
	manifestRaw, _ := json.Marshal(manifest)
	sessionSHA, _ := jcs.SHA256(json.RawMessage(manifestRaw))
	mapping := guardlab.Mapping{ContractVersion: guardlab.Version, MappingID: mapID, SessionID: runID, Entries: []guardlab.Entry{{ScenarioID: "normal-1", TargetBindingID: targetID, PeerKey: peerKey, KeyEpoch: 1, CaptureScopeID: scope, TargetRef: targetID}}}
	scenarios := guardlab.Scenarios{ContractVersion: guardlab.Version, Scenarios: []guardlab.Scenario{{ScenarioID: "normal-1", Family: "normal", Source: "model", PCAPRef: "synthetic.pcap", PCAPSHA256: pcapHash, SourceStart: source, SourceEnd: source.Add(2 * time.Second)}}}

	if plan {
		mapping.Entries = append(mapping.Entries, guardlab.Entry{ScenarioID: "attack-2", TargetBindingID: attackTargetID, PeerKey: peerKey2, KeyEpoch: 1, CaptureScopeID: scope, TargetRef: attackTargetID})
		scenarios.Scenarios = append(scenarios.Scenarios, guardlab.Scenario{ScenarioID: "attack-2", Family: "brute_force", Source: "model", PCAPRef: "synthetic-2.pcap", PCAPSHA256: pcapHash2, SourceStart: source.Add(4 * time.Second), SourceEnd: source.Add(6 * time.Second)})
	}
	if replay {
		mapping.ContractVersion, scenarios.ContractVersion = guardlab.Version11, guardlab.Version11
		for i := range scenarios.Scenarios {
			scenarios.Scenarios[i].CaptureStart = &source
		}
	}
	mapRaw, _ := json.Marshal(mapping)
	scRaw, _ := json.Marshal(scenarios)
	handoff = guardlab.Handoff{State: guardlab.State{ID: runID, EligibilityStatus: "active", EffectiveEligibility: "active", RunStatus: "running", Runnable: true, Revision: 1, AssetID: assetID, BundleID: mapID, SessionSHA256: sessionSHA, EvidenceKind: "lab", ValidUntil: manifest.ValidUntil, StartedAt: &start}, Manifest: manifestRaw, Mapping: mapRaw, Scenarios: scRaw}
	local := guardlab.PrivateMapping{ContractVersion: guardlab.MappingVersion, SessionID: runID, SessionSHA256: sessionSHA, MappingID: mapID, MappingSHA256: manifest.MappingSHA256, ScenarioSHA256: manifest.ScenarioSHA256, BuildSHA256: build, ExtractorSHA256: manifest.Provenance["extractorSha256"], Entries: []guardlab.LocalEntry{{ScenarioID: "normal-1", OriginalLocal: originalLocal, OriginalPeer: originalPeer, CanaryLocal: netip.MustParseAddr("127.0.0.1"), CanaryPeer: canary, PeerKey: peerKey, Direction: "inbound", Transport: "tcp", AddressFamily: "ipv4", Scope: "peer_service", ServicePort: 443}}}
	if replay {
		local.ContractVersion = guardlab.MappingVersion11
	}
	if plan {
		l := local.Entries[0]
		l.ScenarioID = "attack-2"
		l.OriginalPeer = otherPeer
		l.CanaryPeer = otherCanary
		l.PeerKey = peerKey2
		local.Entries = append(local.Entries, l)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	trust := filepath.Join(dir, "trust.json")
	writeFile(t, trust, map[string]string{"test-runner": base64.StdEncoding.EncodeToString(der)})
	canonical, _ := jcs.Canonical(local)
	mp := filepath.Join(dir, "mapping.json")
	writeFile(t, mp, map[string]any{"payload": local, "keyId": "test-runner", "algorithm": "Ed25519", "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))})
	c := config{AssetID: assetID, SensorID: sensor, BootID: boot, CaptureScopeID: scope, Environment: "lab", CaptureScope: scopeService, LocalAddresses: []netip.Addr{originalLocal}, PeerAddresses: []netip.Addr{originalPeer}, ServicePort: 443, SecretFile: secretPath, KeyEpoch: 1, Upload: &uploadConfig{BaseURL: server.URL, CAFile: pki.CAFile, CertificateFile: pki.CertFile, KeyFile: pki.KeyFile, CredentialFile: pki.CredFile, SpoolDir: filepath.Join(dir, "spool")}, Lab: &guardlab.Config{RunID: runID, SessionSHA256: sessionSHA, MappingSHA256: manifest.MappingSHA256, ScenarioID: "normal-1", MappingFile: mp, TrustFile: trust, EventsFile: filepath.Join(dir, "events.jsonl"), Targets: guardlab.TLSConfig{BaseURL: targets.URL, CAFile: pki.CAFile, CertificateFile: pki.CertFile, KeyFile: pki.KeyFile}}}
	if plan {
		c.PeerAddresses = append(c.PeerAddresses, otherPeer)
		c.Lab.Inputs = []guardlab.ReplayInput{{ScenarioID: "normal-1", Path: pcap}, {ScenarioID: "attack-2", Path: pcap2}}
	}
	cp := filepath.Join(dir, "config.json")
	writeFile(t, cp, c)
	out := filepath.Join(dir, "observations.jsonl")
	reportPath := filepath.Join(dir, "report.json")
	args := []string{"-config", cp, "-out", out, "-report", reportPath}
	if plan {
		args = append(args, "-lab-plan")
	} else {
		args = append(args, "-pcap", pcap)
	}
	if shared {
		if e := runCLI(t, args...); e == nil {
			t.Fatal("normal and attack shared one target")
		}
		var failed map[string]any
		b, _ := os.ReadFile(reportPath)
		if json.Unmarshal(b, &failed) != nil || failed["status"] != "failed" || failed["errorCode"] != guardlab.ErrLease.Error() {
			t.Fatal("shared target failure not reported with stable code")
		}
		return
	}
	if e := runCLI(t, args...); e != nil {
		t.Fatal(e)
	}
	windows := backend.HealthWindows()
	if len(windows) == 0 {
		t.Fatal("health windows not uploaded")
	}
	for _, window := range windows {
		if window["healthVersion"] != healthVersion {
			t.Fatal("health version differs from admitted configuration")
		}
		if replay {
			start := window["counterStart"].(map[string]any)
			end := window["counterEnd"].(map[string]any)
			if window["captureSource"] != "file_replay" || window["captureGap"] != false || start["kernelDrops"] != nil || end["kernelDrops"] != nil ||
				start["packetsSeen"] == nil || end["packetsSeen"] == nil || end["packetsSeen"].(float64) < start["packetsSeen"].(float64) ||
				start["capacityDrops"] != float64(0) || end["capacityDrops"] != float64(0) {
				t.Fatalf("invalid replay health window: %+v", window)
			}
		} else if _, present := window["captureSource"]; present {
			t.Fatal("legacy health window acquired a replay source")
		}
	}
	observations := backend.Observations()
	if len(observations) < 2 {
		t.Fatal("missing prefix/final")
	}
	var offline []hostguard.Observation
	e, _ := hostguard.New(hostguard.Config{AssetID: assetID, SensorID: sensor, BootID: boot, CaptureScopeID: scope, Environment: "research", KeyEpoch: 1, LocalAddresses: []netip.Addr{originalLocal}, PeerSecret: keyMaterial, Emit: func(v hostguard.Emission) error { offline = append(offline, v.Observation); return nil }})
	e.Tick(source)
	if err := hostguard.ReadPCAP(pcap, e); err != nil {
		t.Fatal(err)
	}

	if plan {
		second, _ := hostguard.New(hostguard.Config{AssetID: assetID, SensorID: sensor, BootID: boot, CaptureScopeID: scope, Environment: "research", KeyEpoch: 1, LocalAddresses: []netip.Addr{originalLocal}, PeerSecret: keyMaterial, Emit: func(v hostguard.Emission) error { offline = append(offline, v.Observation); return nil }})
		second.Tick(source)
		if err := hostguard.ReadPCAP(pcap2, second); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	if len(offline) != len(observations) {
		t.Fatal("observation count changed")
	}
	// 与 guardreplaydiff 同一实现对拍：research 离线提取对 lab 回放输出，只忽略已登记的 lab 差异字段。
	var offlineLines bytes.Buffer
	for _, o := range offline {
		line, _ := json.Marshal(o)
		offlineLines.Write(append(line, '\n'))
	}
	labOut, _ := os.ReadFile(out)
	reportRaw, _ := os.ReadFile(reportPath)
	diff, identical, err := replaydiff.Compare(bytes.NewReader(offlineLines.Bytes()), bytes.NewReader(labOut), reportRaw)
	if err != nil || !identical || diff["compared"] != len(offline) {
		t.Fatalf("guardreplaydiff lab/research 对拍失败: %v %v", diff, err)
	}
	// 篡改任一特征必须被发现，证明对拍没有把特征列入忽略项。
	parts := bytes.SplitN(labOut, []byte("\n"), 2)
	var tampered hostguard.Observation
	if err = json.Unmarshal(parts[0], &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Features.PacketsInbound++
	first, _ := json.Marshal(tampered)
	if _, identical, err = replaydiff.Compare(bytes.NewReader(offlineLines.Bytes()), bytes.NewReader(append(append(first, '\n'), parts[1]...)), reportRaw); err != nil || identical {
		t.Fatal("tampered lab feature not detected")
	}
	for i, b := range observations {
		var o hostguard.Observation
		json.Unmarshal(b, &o)
		wantRef := targetID
		if o.PeerKey == peerKey2 {
			wantRef = attackTargetID
		}
		if o.PeerKey != peerKey && (!plan || o.PeerKey != peerKey2) || o.TargetRef == nil || *o.TargetRef != wantRef || o.Environment != "lab" {
			t.Fatal("missing mapped lease")
		}

		if seen[o.ObservationID] {
			t.Fatal("scenario observation ID collision")
		}
		seen[o.ObservationID] = true
		if plan {
			o.ObservationID = offline[i].ObservationID
			o.FlowID = offline[i].FlowID
			o.ParentConnectionID = offline[i].ParentConnectionID
		}
		o.FirstSeenAt = o.FirstSeenAt.Add(-offset)
		o.LastPacketAt = o.LastPacketAt.Add(-offset)
		o.AsOf = o.AsOf.Add(-offset)
		o.EmittedAt = time.Time{}
		o.TargetRef = nil
		o.TargetExpiresAt = nil
		o.PeerKey = offline[i].PeerKey
		o.Environment = "research"
		o.Quality.ClockSkewMs = nil
		offline[i].EmittedAt = time.Time{}
		if !reflect.DeepEqual(o, offline[i]) {
			t.Fatalf("offline feature/order difference %d", i)
		}
	}
	if e := runCLI(t, "-config", cp, "-drain"); e != nil {
		t.Fatal(e)
	}
	if len(backend.Observations()) != len(observations) {
		t.Fatal("drain duplicated observations")
	}
	runnable.Store(false)
	if e := runCLI(t, "-config", cp, "-drain"); e == nil {
		t.Fatal("revoked session drained")
	}
}

func TestHealthProtocolRequiresAdmittedPlanAndSubjectVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		admitted bool
		inputs   int
		version  string
		want     string
		source   string
	}{
		{"unadmitted", false, 1, capturehealth.ReplayVersion, capturehealth.Version, ""},
		{"single-replay", true, 0, capturehealth.ReplayVersion, capturehealth.Version, ""},
		{"legacy-plan", true, 1, capturehealth.Version, capturehealth.Version, ""},
		{"unknown-version", true, 1, "unsupported", capturehealth.Version, ""},
		{"replay-plan", true, 1, capturehealth.ReplayVersion, capturehealth.ReplayVersion, "file_replay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab := guardlab.Config{Inputs: make([]guardlab.ReplayInput, tc.inputs)}
			c := config{Environment: "lab", Lab: &lab}
			if tc.admitted {
				c.labSession = &guardlab.Session{Config: lab, Manifest: guardlab.Manifest{ProtocolVersions: map[string]string{"health": tc.version}}}
			}
			if version, source := healthProtocol(c); version != tc.want || source != tc.source {
				t.Fatalf("protocol = %q/%q, want %q/%q", version, source, tc.want, tc.source)
			}
		})
	}
}

func TestAggregateLabHealthDetectsIndividualStallAndRetainsCompletedCounters(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		age       time.Duration
		completed bool
		gap       bool
		wantGap   bool
	}{
		{"boundary", capturehealth.MaxWindow, false, false, false},
		{"stalled", capturehealth.MaxWindow + time.Nanosecond, false, false, true},
		{"explicit-gap", time.Second, false, true, true},
		{"completed", time.Hour, true, false, false},
		{"completed-with-pending-gap", time.Hour, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			samples := []hostguard.LiveSample{{At: now, PacketsSeen: 13, CapacityDrops: 2, LateCount: 1},
				{At: now.Add(-tc.age), PacketsSeen: 17, CapacityDrops: 3, LateCount: 4, Gap: tc.gap}}
			total := aggregateLabHealth(samples, []bool{false, tc.completed}, now)
			if total.Gap != tc.wantGap || total.PacketsSeen != 30 || total.CapacityDrops != 5 || total.LateCount != 5 || total.DropsKnown || !total.At.Equal(now) {
				t.Fatalf("aggregated counters/gap: %+v", total)
			}
		})
	}
}

func TestLabHealthSamplerAggregatesConcurrentChildrenOnOneClock(t *testing.T) {
	const children = 18
	var mu sync.Mutex
	samples := make([]hostguard.LiveSample, children)
	completed := make([]bool, children)
	at := time.Now()
	for i := range samples {
		samples[i].At = at
	}
	stop := make(chan struct{})
	first := make(chan hostguard.LiveSample, 1)
	done := make(chan hostguard.LiveSample, 1)
	go func() {
		done <- sampleLabHealth(stop, time.Millisecond, &mu, samples, completed, func(s hostguard.LiveSample) {
			select {
			case first <- s:
			default:
			}
		})
	}()
	var wg sync.WaitGroup
	for i := range samples {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			mu.Lock()
			samples[index] = hostguard.LiveSample{At: at, PacketsSeen: 1}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("independent sampler did not emit")
	}
	close(stop)
	last := <-done
	if last.Gap || last.PacketsSeen != children {
		t.Fatalf("concurrent counter snapshot: %+v", last)
	}
}
