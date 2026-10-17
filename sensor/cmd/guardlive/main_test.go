package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardup/guarduptest"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

const (
	assetID = "00000000-0000-4000-8000-000000000001"
	sensor  = "00000000-0000-4000-8000-000000000002"
	scope   = "00000000-0000-4000-8000-000000000004"
)

func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	flag.CommandLine = flag.NewFlagSet("guardlive", flag.ContinueOnError)
	os.Args = append([]string{"guardlive"}, args...)
	stdout := os.Stdout
	devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devnull
	defer func() { os.Stdout = stdout; devnull.Close() }()
	return run()
}

func writeFile(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSONL(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		out = append(out, append([]byte(nil), s.Bytes()...))
	}
	return out
}

// 端到端：冻结 PCAP 1 倍速回放 → all_inbound_tcp 范围 → mTLS 上传；结果与离线提取逐字段一致，上传不丢不重。
func TestPCAPReplayUploadMatchesOffline(t *testing.T) {
	dir := t.TempDir()
	host, p1, p2 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("203.0.113.9")
	base := time.Date(2017, 7, 7, 15, 0, 0, 345678000, time.UTC)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	var specs []synth.Spec
	for i := 0; i < 30; i++ { // p1 扫描 30 个端口，本机 RST 回应
		specs = append(specs, synth.Spec{TS: at(i * 40), Src: p1, Dst: host, SPort: 41000, DPort: uint16(1000 + i), Proto: 6, Flags: synth.SYN},
			synth.Spec{TS: at(i*40 + 1), Src: host, Dst: p1, SPort: uint16(1000 + i), DPort: 41000, Proto: 6, Flags: synth.RST | synth.ACK})
	}
	specs = append(specs,
		synth.Spec{TS: at(1300), Src: p2, Dst: host, SPort: 52000, DPort: 80, Proto: 6, Flags: synth.SYN},
		synth.Spec{TS: at(1301), Src: host, Dst: p2, SPort: 80, DPort: 52000, Proto: 6, Flags: synth.SYN | synth.ACK},
		synth.Spec{TS: at(1302), Src: p2, Dst: host, SPort: 52000, DPort: 80, Proto: 6, Flags: synth.ACK},
		synth.Spec{TS: at(1400), Src: host, Dst: p2, SPort: 60000, DPort: 443, Proto: 6, Flags: synth.SYN}, // 本机主动外连：范围外
		synth.Spec{TS: at(1500), Src: p2, Dst: host, SPort: 53000, DPort: 53, Proto: 17, Payload: 20},      // UDP：范围外
		synth.Spec{TS: at(2600), Src: p2, Dst: host, SPort: 52000, DPort: 80, Proto: 6, Flags: synth.PSH | synth.ACK, Payload: 200},
	)
	frames := make([]synth.Frame, len(specs))
	for i, s := range specs {
		frames[i] = synth.Build(s, 256)
	}
	pcapPath := filepath.Join(dir, "segment.pcap")
	f, _ := os.Create(pcapPath)
	if err := synth.WritePcap(f, 256, frames); err != nil {
		t.Fatal(err)
	}
	f.Close()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("synthetic-replay-key-no-real-credential-000"), 0o600)
	exe, _ := os.Executable()
	eb, _ := os.ReadFile(exe)
	sum := sha256.Sum256(eb)
	pki := guarduptest.NewPKI(t)
	backend := guarduptest.NewBackend(guarduptest.Approved{SensorID: sensor, ConfigID: "00000000-0000-4000-8000-0000000000c1", ConfigHash: strings.Repeat("c", 64), CaptureScopeID: scope, AddressFamily: "ipv4",
		BuildSha256: hex.EncodeToString(sum[:]), ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256, HealthVersion: capturehealth.Version, MaxBatchSize: 5})
	srv := backend.Start(t, pki)
	boot := "00000000-0000-4000-8000-0000000000b1"
	cfg := map[string]any{"assetId": assetID, "sensorId": sensor, "bootId": boot, "captureScopeId": scope, "environment": "research", "captureScope": "all_inbound_tcp",
		"localAddresses": []string{host.String()}, "secretFile": secret, "keyEpoch": 1,
		"upload": map[string]any{"baseUrl": srv.URL, "caFile": pki.CAFile, "certificateFile": pki.CertFile, "keyFile": pki.KeyFile, "credentialFile": pki.CredFile, "spoolDir": filepath.Join(dir, "spool"), "healthWindowMs": 500}}
	cfgPath := filepath.Join(dir, "config.json")
	writeFile(t, cfgPath, cfg)
	out, report := filepath.Join(dir, "replay.jsonl"), filepath.Join(dir, "report.json")
	if err := runCLI(t, "-config", cfgPath, "-pcap", pcapPath, "-out", out, "-report", report); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Status            string `json:"status"`
		Emitted           int    `json:"emitted"`
		OutOfScopeSkipped int    `json:"outOfScopeSkipped"`
		Replay            struct {
			TimeOffsetMicros int64 `json:"timeOffsetMicros"`
			Speed            int   `json:"speed"`
		} `json:"replay"`
		Upload struct {
			Accepted, Duplicates, SealedBatches, AckedBatches, PendingBatches, HealthSent int
		} `json:"upload"`
	}
	rb, _ := os.ReadFile(report)
	if err := json.Unmarshal(rb, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Status != "completed" || rep.Replay.Speed != 1 || rep.Emitted == 0 || rep.OutOfScopeSkipped == 0 {
		t.Fatalf("运行摘要异常: %s", rb)
	}
	if rep.Upload.Accepted != rep.Emitted || rep.Upload.Duplicates != 0 || rep.Upload.PendingBatches != 0 || rep.Upload.AckedBatches != rep.Upload.SealedBatches || rep.Upload.HealthSent == 0 {
		t.Fatalf("上传统计异常: %s", rb)
	}
	lines := readJSONL(t, out)
	got := backend.Observations()
	if len(lines) != rep.Emitted || len(got) != len(lines) {
		t.Fatalf("本地 %d / 上传 %d / 摘要 %d 不一致", len(lines), len(got), rep.Emitted)
	}
	for i := range lines {
		if !bytes.Equal(lines[i], got[i]) {
			t.Fatalf("第 %d 条上传内容与本地输出不同", i)
		}
	}
	for i, s := range backend.Sequences() {
		if s != int64(i+1) {
			t.Fatal("批次序号不连续")
		}
	}
	for _, s := range backend.HealthStatuses() {
		if s != "healthy" { // 假后端只校验链；真实后端会因回放历史丢包未知判为 COUNTER_UNKNOWN
			t.Fatalf("健康链断裂: %s", s)
		}
	}
	// 离线参照：同一文件、同一身份/密钥的因果引擎输出，按同一范围过滤后逐字段比对。
	var offline []hostguard.Observation
	e, err := hostguard.New(hostguard.Config{AssetID: assetID, SensorID: sensor, BootID: boot, CaptureScopeID: scope, Environment: "research", KeyEpoch: 1,
		PeerSecret: []byte("synthetic-replay-key-no-real-credential-000"), LocalAddresses: []netip.Addr{host},
		Emit: func(v hostguard.Emission) error {
			if v.Observation.Transport == "tcp" && v.Observation.Direction != "outbound" {
				offline = append(offline, v.Observation)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err = hostguard.ReadPCAP(pcapPath, e); err != nil {
		t.Fatal(err)
	}
	if len(offline) != len(lines) {
		t.Fatalf("离线 %d 条，回放 %d 条", len(offline), len(lines))
	}
	shift := time.Duration(rep.Replay.TimeOffsetMicros) * time.Microsecond
	for i, line := range lines {
		var o hostguard.Observation
		if err := json.Unmarshal(line, &o); err != nil {
			t.Fatal(err)
		}
		if o.EmittedAt.Before(o.AsOf) || o.Environment != "research" {
			t.Fatal("emittedAt 必须是不早于事件时间的墙钟")
		}
		// clockSkewMs 与 emittedAt 一样是在线运行时测值：回放必须带新鲜心跳偏差，离线没有服务端时钟保持 null。
		if o.Quality.ClockSkewMs == nil || math.Abs(*o.Quality.ClockSkewMs) > 1000 || offline[i].Quality.ClockSkewMs != nil {
			t.Fatalf("第 %d 条回放缺少可信实测偏差或离线伪造了偏差", i)
		}
		o.Quality.ClockSkewMs = nil
		o.FirstSeenAt, o.LastPacketAt, o.AsOf, o.EmittedAt = o.FirstSeenAt.Add(-shift), o.LastPacketAt.Add(-shift), o.AsOf.Add(-shift), time.Time{}
		want := offline[i]
		want.EmittedAt = time.Time{}
		// JSON 往返后的时间去掉单调时钟与时区指针差异再比较。
		wb, _ := json.Marshal(want)
		gb, _ := json.Marshal(o)
		if !bytes.Equal(wb, gb) {
			t.Fatalf("第 %d 条回放与离线不一致\n got=%s\nwant=%s", i, gb, wb)
		}
	}
	// 同一 bootId 不能重新采集；-drain 只续传未确认批次。
	if err := runCLI(t, "-config", cfgPath, "-pcap", pcapPath, "-out", filepath.Join(dir, "again.jsonl")); err == nil || !strings.Contains(err.Error(), "已有 spool") {
		t.Fatalf("重复 bootId 未拒绝: %v", err)
	}
	if err := runCLI(t, "-config", cfgPath, "-drain", "-drain-timeout", "5s"); err != nil {
		t.Fatal(err)
	}
	if len(backend.Observations()) != len(lines) {
		t.Fatal("drain 产生了重复入库")
	}
}

func TestConfigBoundaries(t *testing.T) {
	dir := t.TempDir()
	bad := []map[string]any{
		{"environment": "production"},
		{"captureScope": "everything"},
		{"captureScope": "all_inbound_tcp", "servicePort": 22},
		{"captureScope": "all_inbound_tcp", "peerAddresses": []string{"198.51.100.2"}},
		{"localAddresses": []string{"0.0.0.0"}},
		{"unknownField": true},
	}
	for i, extra := range bad {
		c := map[string]any{"assetId": assetID, "sensorId": sensor, "bootId": "00000000-0000-4000-8000-0000000000b2", "captureScopeId": scope, "localAddresses": []string{"192.0.2.1"}}
		for k, v := range extra {
			c[k] = v
		}
		path := filepath.Join(dir, "c.json")
		os.Remove(path)
		writeFile(t, path, c)
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("第 %d 个越界配置未拒绝", i)
		}
	}
	c := map[string]any{"assetId": assetID, "sensorId": sensor, "bootId": "00000000-0000-4000-8000-0000000000b2", "captureScopeId": scope, "environment": "lab", "localAddresses": []string{"192.0.2.1"}, "secretFile": "/nonexistent"}
	path := filepath.Join(dir, "lab.json")
	writeFile(t, path, c)
	if err := runCLI(t, "-config", path, "-pcap", "/nonexistent.pcap", "-out", filepath.Join(dir, "x.jsonl")); err == nil || !strings.Contains(err.Error(), "research") {
		t.Fatalf("lab 文件回放未拒绝: %v", err)
	}
	if err := runCLI(t, "-config", path, "-pcap", "a", "-trace", "b", "-out", "c"); err == nil {
		t.Fatal("多模式未拒绝")
	}
}

// 演示范围不能退回 en0、真实资产或宽泛地址；无需打开任何捕获句柄。
func TestLabPeerConfigBoundaries(t *testing.T) {
	valid := map[string]any{"assetId": assetID, "sensorId": sensor, "bootId": "00000000-0000-4000-8000-0000000000b2", "captureScopeId": scope,
		"environment": "lab", "captureScope": "lab_peer_tcp", "localAddresses": []string{"100.64.0.10"}, "peerAddresses": []string{"100.64.0.20"},
		"servicePorts": []int{55280, 55300}, "interface": "utun9", "captureLockDir": "/private-demo/locks"}
	d := t.TempDir()
	file := filepath.Join(d, "lab.json")
	writeFile(t, file, valid)
	if _, err := loadConfig(file); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"environment": "authorized", "interface": "en0", "captureLockDir": "", "peerAddresses": []string{"8.8.8.8"}, "servicePorts": []int{22}, "servicePort": 55280} {
		c := map[string]any{}
		for k, v := range valid {
			c[k] = v
		}
		c[key] = value
		writeFile(t, file, c)
		if _, err := loadConfig(file); err == nil {
			t.Fatalf("越界 %s 未拒绝", key)
		}
	}
}
