package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardup"
	"github.com/xyh/cyber-security/sensor/internal/guardup/guarduptest"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// scriptedLive 只返回内存中的合成帧、超时和计数；不打开任何捕获接口。
type liveStep struct {
	ms       int
	packet   bool
	err      error
	drops    uint64
	dropsErr error
}

type scriptedLive struct {
	base, now time.Time
	steps     []liveStep
	current   liveStep
	reads     int
	cancel    context.CancelFunc
}

func (s *scriptedLive) Next() ([]byte, gopacket.CaptureInfo, error) {
	if s.reads == len(s.steps) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	s.current = s.steps[s.reads]
	s.reads++
	s.now = s.base.Add(time.Duration(s.current.ms) * time.Millisecond)
	if s.cancel != nil {
		s.cancel()
	}
	if !s.current.packet {
		err := s.current.err
		if err == nil {
			err = hostguard.ErrCaptureTimeout
		}
		return nil, gopacket.CaptureInfo{}, err
	}
	f := synth.Build(synth.Spec{TS: s.now, Src: netip.MustParseAddr("198.51.100.2"), Dst: netip.MustParseAddr("192.0.2.1"),
		SPort: 40000, DPort: 80, Proto: 6, Flags: synth.SYN}, 256)
	return f.Data, gopacket.CaptureInfo{Timestamp: s.now, Length: f.WireLen, CaptureLength: len(f.Data)}, nil
}

func (s *scriptedLive) Drops() (uint64, error) { return s.current.drops, s.current.dropsErr }

func liveEngine(t *testing.T, maxBuffered int) *hostguard.Engine {
	t.Helper()
	e, err := hostguard.New(hostguard.Config{AssetID: assetID, SensorID: sensor, BootID: guardup.NewUUID(), CaptureScopeID: scope,
		Environment: "authorized", LocalAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		PeerSecret: []byte("synthetic-live-health-key-no-real-secret"), KeyEpoch: 1, MaxBufferedPackets: maxBuffered,
		Emit: func(hostguard.Emission) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// 直接走现场运行器、正式观察器与上传器，严格替身后端按 GuardHealth 校验收到的窗口。
// 模拟 idle 时仍捕获、真实计数变化与中途故障；不以手工拼装的健康样本替代实时循环。
func TestLiveSourceHealthUpload(t *testing.T) {
	unknown := errors.New("synthetic statistics unavailable")
	readFailure := errors.New("synthetic capture failure")
	for _, tc := range []struct {
		name        string
		steps       []liveStep
		maxBuffered int
		want        []string
		wantErr     error
		packets     float64
	}{
		{"idle", []liveStep{{ms: 500}, {ms: 1000}, {ms: 1500, err: io.EOF}}, 0, []string{"healthy", "healthy"}, nil, 0},
		{"packets", []liveStep{{ms: 100, packet: true}, {ms: 500, packet: true}, {ms: 1000}, {ms: 1500, err: io.EOF}}, 0, []string{"healthy", "healthy"}, nil, 2},
		{"kernel-drop", []liveStep{{ms: 500, drops: 1}, {ms: 1000, drops: 1}, {ms: 2000, drops: 1, err: io.EOF}}, 0, []string{"CAPTURE_GAP", "healthy"}, nil, 0},
		{"unknown-middle", []liveStep{{ms: 500, dropsErr: unknown}, {ms: 1000}, {ms: 2000, err: io.EOF}}, 0, []string{"CAPTURE_GAP", "healthy"}, nil, 0},
		{"unknown-tail", []liveStep{{ms: 500}, {ms: 1000, err: io.EOF, dropsErr: unknown}}, 0, []string{"CAPTURE_GAP"}, nil, 0},
		{"counter-reset", []liveStep{{ms: 100, drops: 5}, {ms: 500}, {ms: 1000, err: io.EOF}}, 0, []string{"CAPTURE_GAP"}, nil, 0},
		{"stall", []liveStep{{ms: 6000}, {ms: 6500, err: io.EOF}}, 0, []string{"CAPTURE_GAP", "CAPTURE_GAP", "healthy"}, nil, 0},
		{"capacity-drop", []liveStep{{ms: 10, packet: true}, {ms: 20, packet: true}, {ms: 1000, err: io.EOF}}, 1, []string{"CAPTURE_DROPS"}, nil, 2},
		{"read-failure", []liveStep{{ms: 500, err: readFailure}}, 0, []string{"CAPTURE_GAP"}, readFailure, 0},
		{"final-drop", []liveStep{{ms: 500}, {ms: 1000, err: io.EOF, drops: 1}}, 0, []string{"CAPTURE_GAP"}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := guarduptest.NewPKI(t)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			build, err := digest(exe)
			if err != nil {
				t.Fatal(err)
			}
			backend := guarduptest.NewBackend(guarduptest.Approved{SensorID: sensor, ConfigID: guardup.NewUUID(), ConfigHash: strings.Repeat("c", 64),
				CaptureScopeID: scope, AddressFamily: "ipv4", BuildSha256: build, ContractVersion: hostguard.Version,
				ProfileSha256: hostguard.FeatureProfileSHA256, HealthVersion: capturehealth.Version, MaxBatchSize: 5})
			base := time.Now().UTC().Add(-10 * time.Second).Truncate(time.Millisecond)
			end := base.Add(time.Duration(tc.steps[len(tc.steps)-1].ms) * time.Millisecond)
			backend.SetStrictHealth(func() time.Time { return end.Add(100 * time.Millisecond) })
			srv := backend.Start(t, pki)
			c := config{AssetID: assetID, SensorID: sensor, BootID: guardup.NewUUID(), CaptureScopeID: scope, Environment: "authorized",
				LocalAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Upload: &uploadConfig{BaseURL: srv.URL,
					CAFile: pki.CAFile, CertificateFile: pki.CertFile, KeyFile: pki.KeyFile, CredentialFile: pki.CredFile,
					SpoolDir: filepath.Join(t.TempDir(), "spool")}}
			u, err := startUpload(c, true, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer u.cancel()
			o, err := u.healthObserver(c)
			if err != nil {
				t.Fatal(err)
			}
			s := &scriptedLive{base: base, now: base, steps: tc.steps}
			err = runLiveSource(context.Background(), s, liveEngine(t, tc.maxBuffered), func() time.Time { return s.now }, nil, o, u.up.Err)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("capture error = %v, want %v", err, tc.wantErr)
			}
			if err = u.finish(); err != nil {
				t.Fatal(err)
			}
			if got := backend.HealthStatuses(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("health status = %v, want %v", got, tc.want)
			}
			windows := backend.HealthWindows()
			if windows[0]["intervalStart"] != base.Format(time.RFC3339Nano) || windows[len(windows)-1]["intervalEnd"] != end.Format(time.RFC3339Nano) {
				t.Fatal("健康链未覆盖首包前基线或退出尾窗")
			}
			for i, w := range windows {
				if w["healthVersion"] != capturehealth.Version || w["captureSource"] != nil || w["observerSessionId"] != o.Session() || w["sequence"] != float64(i+1) {
					t.Fatalf("现场窗口协议/身份/序号错误: %+v", w)
				}
			}
			last := windows[len(windows)-1]["counterEnd"].(map[string]any)
			if last["packetsSeen"] != tc.packets {
				t.Fatalf("丢失读取计数: %+v", last)
			}
			if tc.name == "unknown-tail" && last["kernelDrops"] != nil {
				t.Fatal("退出时未知计数被旧值覆盖")
			}
			if tc.name == "capacity-drop" && last["capacityDrops"] != float64(1) {
				t.Fatalf("引擎容量丢弃未上报: %+v", last)
			}
		})
	}
}

func testLiveObserver(t *testing.T, emit func(capturehealth.Window) error) *capturehealth.Observer {
	t.Helper()
	o, err := capturehealth.New(capturehealth.Identity{AssetID: assetID, SensorID: sensor, CaptureScopeID: scope,
		ConfigSha256: strings.Repeat("c", 64), BuildSha256: strings.Repeat("b", 64)}, capturehealth.Options{NewID: guardup.NewUUID, Emit: emit})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestLiveSourceStopsOnHealthFailure(t *testing.T) {
	failure := errors.New("synthetic health queue failure")
	for _, phase := range []string{"window", "tail", "upload-idle"} {
		t.Run(phase, func(t *testing.T) {
			base := time.Now().UTC()
			s := &scriptedLive{base: base, now: base, steps: []liveStep{{ms: 1000}, {ms: 2000}}}
			calls := 0
			o := testLiveObserver(t, func(capturehealth.Window) error { calls++; return failure })
			var check func() error
			if phase == "tail" {
				s.steps = []liveStep{{ms: 500, err: io.EOF}}
			}
			if phase == "upload-idle" {
				s.steps[0].ms = 100
				check = func() error {
					if s.reads > 0 {
						return failure
					}
					return nil
				}
			}
			err := runLiveSource(context.Background(), s, liveEngine(t, 0), func() time.Time { return s.now }, nil, o, check)
			wantCalls := 1
			if phase == "upload-idle" {
				wantCalls = 0
			}
			if !errors.Is(err, failure) || s.reads != 1 || calls != wantCalls {
				t.Fatalf("健康故障未立即停止或重复签发: err=%v reads=%d emits=%d", err, s.reads, calls)
			}
		})
	}
}

func TestLiveSourceCancellationClosesPartialWindow(t *testing.T) {
	base := time.Now().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &scriptedLive{base: base, now: base, steps: []liveStep{{ms: 250}, {ms: 1000}}, cancel: cancel}
	var windows []capturehealth.Window
	o := testLiveObserver(t, func(w capturehealth.Window) error { windows = append(windows, w); return nil })
	if err := runLiveSource(ctx, s, liveEngine(t, 0), func() time.Time { return s.now }, nil, o, nil); err != nil {
		t.Fatal(err)
	}
	if s.reads != 1 || len(windows) != 1 || windows[0].CaptureGap || windows[0].IntervalEnd != base.Add(250*time.Millisecond).Format(time.RFC3339Nano) {
		t.Fatalf("取消后尾窗不完整: reads=%d windows=%+v", s.reads, windows)
	}
}

func TestLiveSourceRejectsReplayHealthProtocol(t *testing.T) {
	o, err := capturehealth.New(capturehealth.Identity{AssetID: assetID, SensorID: sensor, CaptureScopeID: scope,
		ConfigSha256: strings.Repeat("c", 64), BuildSha256: strings.Repeat("b", 64)}, capturehealth.Options{
		Version: capturehealth.ReplayVersion, Source: "file_replay", NewID: guardup.NewUUID, Emit: func(capturehealth.Window) error { t.Fatal("现场不应签发回放窗口"); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptedLive{}
	if err = runLiveSource(context.Background(), s, liveEngine(t, 0), time.Now, nil, o, nil); err == nil || s.reads != 0 {
		t.Fatal("现场错误复用了回放健康协议")
	}
}
