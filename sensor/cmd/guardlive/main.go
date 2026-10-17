// guardlive 只在显式授权的接口和期限内采集 v5 观察，或以 1 倍速只读回放冻结 PCAP；
// 可选经 mTLS 上传 v2 观察批次与连续健康窗口。不持有防火墙权限，不接入执行器。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardlab"
	"github.com/xyh/cyber-security/sensor/internal/guardup"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

const (
	scopeService    = "service"
	scopeAllInbound = "all_inbound_tcp"
	scopeLabPeer    = "lab_peer_tcp"
)

// uploadConfig 只含路径与地址；凭据、私钥由文件提供，不经命令行或日志。
type uploadConfig struct {
	BaseURL         string `json:"baseUrl"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	CredentialFile  string `json:"credentialFile"`
	SpoolDir        string `json:"spoolDir"`
	HealthWindowMs  int    `json:"healthWindowMs"`
}

type config struct {
	AssetID           string            `json:"assetId"`
	SensorID          string            `json:"sensorId"`
	BootID            string            `json:"bootId"`
	CaptureScopeID    string            `json:"captureScopeId"`
	Environment       string            `json:"environment"`
	CaptureScope      string            `json:"captureScope"`
	LocalAddresses    []netip.Addr      `json:"localAddresses"`
	PeerAddresses     []netip.Addr      `json:"peerAddresses"`
	ServicePorts      []uint16          `json:"servicePorts,omitempty"`
	LiveTargets       *liveTargetConfig `json:"liveTargets,omitempty"`
	ServicePort       uint16            `json:"servicePort"`
	ServiceEndpoint   string            `json:"serviceEndpoint"`
	SecretFile        string            `json:"secretFile"`
	KeyEpoch          int               `json:"keyEpoch"`
	Interface         string            `json:"interface"`
	CaptureLockDir    string            `json:"captureLockDir,omitempty"`
	AllowedInterfaces []string          `json:"allowedInterfaces"`
	AuthorizedUntil   time.Time         `json:"authorizedUntil"`
	Upload            *uploadConfig     `json:"upload"`
	Lab               *guardlab.Config  `json:"lab,omitempty"`
	labSession        *guardlab.Session
}

func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("授权配置无效")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return c, fmt.Errorf("授权配置存在尾随内容")
	}
	// 旧配置没有这两项时保持原 research/单服务语义。
	if c.Environment == "" {
		c.Environment = "research"
	}
	if c.CaptureScope == "" {
		c.CaptureScope = scopeService
	}
	if c.Environment != "research" && c.Environment != "lab" && c.Environment != "authorized" {
		return c, fmt.Errorf("环境必须为 research、lab 或 authorized")
	}
	if c.Lab != nil && c.Environment != "lab" {
		return c, guardlab.ErrAdmission
	}
	switch c.CaptureScope {
	case scopeLabPeer:
		if c.Environment != "lab" || len(c.LocalAddresses) != 1 || len(c.PeerAddresses) != 1 || len(c.ServicePorts) == 0 || len(c.ServicePorts) > 128 || c.ServicePort != 0 || c.ServiceEndpoint != "" || c.Lab != nil {
			return c, fmt.Errorf("lab_peer_tcp 范围无效")
		}
		tailnet := netip.MustParsePrefix("100.64.0.0/10")
		if !tailnet.Contains(c.LocalAddresses[0]) || !tailnet.Contains(c.PeerAddresses[0]) || c.LocalAddresses[0] == c.PeerAddresses[0] || !regexp.MustCompile(`^utun[0-9]+$`).MatchString(c.Interface) || c.CaptureLockDir == "" {
			return c, fmt.Errorf("lab 必须为独立的 Tailscale IPv4、utun 接口与采集锁目录")
		}
		seen := map[uint16]bool{}
		for _, p := range c.ServicePorts {
			if p < 1024 || seen[p] {
				return c, fmt.Errorf("lab 端口无效")
			}
			seen[p] = true
		}
	case scopeService:
	case scopeAllInbound:
		// 全入站范围不接受对端/端口白名单，避免与单服务语义混用。
		if len(c.PeerAddresses) != 0 || c.ServicePort != 0 || c.ServiceEndpoint != "" {
			return c, fmt.Errorf("all_inbound_tcp 不能同时登记对端或服务端口")
		}
	default:
		return c, fmt.Errorf("captureScope 必须为 service、all_inbound_tcp 或 lab_peer_tcp")
	}
	if c.CaptureScope != scopeLabPeer && (len(c.ServicePorts) > 0 || c.LiveTargets != nil) {
		return c, fmt.Errorf("现场目标配置只适用于 lab_peer_tcp")
	}
	for _, addr := range c.LocalAddresses {
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
			return c, fmt.Errorf("本机地址不明确")
		}
	}
	return c, nil
}

// inScope 决定观察是否写出/上传：all_inbound_tcp 只保留 TCP 且非本机主动发起（outbound）的连接；
// 方向未知的段仍保留，由后端按 not_applicable 处理。service 范围已由 BPF 收窄，不再过滤。
func inScope(c config, o hostguard.Observation) bool {
	if c.CaptureScope != scopeAllInbound {
		return true
	}
	return o.Transport == "tcp" && o.Direction != "outbound"
}

func addressFamily(addrs []netip.Addr) (string, error) {
	af := ""
	for _, a := range addrs {
		v := "ipv4"
		if a.Unmap().Is6() {
			v = "ipv6"
		}
		if af != "" && af != v {
			return "", fmt.Errorf("一个捕获域只允许一个地址族")
		}
		af = v
	}
	if af == "" {
		return "", fmt.Errorf("缺少本机地址")
	}
	return af, nil
}

type uploadSession struct {
	up      *guardup.Uploader
	remote  guardup.RemoteConfig
	build   string
	cancel  context.CancelFunc
	done    chan error
	timeout time.Duration
}

// startUpload 拉取并核对已批准配置，打开本 boot 的 spool 并启动发送循环。
// fresh=true 时要求 spool 为空：同一 bootId 重新采集会生成相同观察 ID 但不同 emittedAt，只能换新 bootId。
func startUpload(c config, fresh bool, timeout time.Duration) (*uploadSession, error) {
	u := c.Upload
	if u == nil {
		return nil, fmt.Errorf("缺少 upload 配置")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	build, err := digest(exe)
	if err != nil {
		return nil, err
	}
	af, err := addressFamily(c.LocalAddresses)
	if err != nil {
		return nil, err
	}
	client, err := guardup.NewClient(guardup.ClientConfig{BaseURL: u.BaseURL, SensorID: c.SensorID, CAFile: u.CAFile, CertificateFile: u.CertificateFile, KeyFile: u.KeyFile, CredentialFile: u.CredentialFile})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remote, err := client.Config(ctx)
	cancel()
	if err != nil {
		return nil, err
	}
	healthVersion, _ := healthProtocol(c)
	if err = guardup.VerifyRemote(remote, c.CaptureScopeID, af, build, healthVersion); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(u.SpoolDir) {
		return nil, fmt.Errorf("spoolDir 必须为绝对路径")
	}
	_, statErr := os.Stat(filepath.Join(u.SpoolDir, c.BootID, "meta.json"))
	if fresh && statErr == nil {
		return nil, fmt.Errorf("该 bootId 已有 spool：重新采集须换新 bootId，续传未确认批次用 -drain")
	}
	if !fresh && statErr != nil {
		return nil, fmt.Errorf("该 bootId 没有可续传的 spool")
	}
	if c.Lab != nil {
		if c.labSession == nil {
			return nil, guardlab.ErrAdmission
		}
		if err = c.labSession.Check(context.Background(), time.Now()); err != nil {
			return nil, err
		}
		if err = c.labSession.BindSpool(u.SpoolDir, fresh); err != nil {
			return nil, err
		}
	} else if _, e := os.Lstat(filepath.Join(u.SpoolDir, c.BootID, "lab-binding.json")); !os.IsNotExist(e) {
		return nil, guardlab.ErrContinuity
	}
	spool, err := guardup.OpenSpool(u.SpoolDir, guardup.SpoolMeta{SensorID: c.SensorID, BootID: c.BootID, ConfigID: remote.ConfigID, ContractVersion: hostguard.Version, ProfileSha256: hostguard.FeatureProfileSHA256}, remote.Config.Limits.MaxBatchSize)
	if err != nil {
		return nil, err
	}
	up, err := guardup.New(guardup.Options{Client: client, Spool: spool, Remote: remote, BootID: c.BootID, Version: "guardlive/" + hostguard.Version})
	if err != nil {
		return nil, err
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	s := &uploadSession{up: up, remote: remote, build: build, cancel: runCancel, done: make(chan error, 1), timeout: timeout}
	go func() { s.done <- up.Run(runCtx) }()
	if fresh {
		// 首个心跳完成前导出的快照只能带 null 偏差；采集开始前最多等待 10 秒取得首个测值。
		deadline := time.Now().Add(10 * time.Second)
		for _, ok := up.Skew(); !ok && time.Now().Before(deadline); _, ok = up.Skew() {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return s, nil
}

// finish 等待全部批次与健康窗口确认；超时则保留 spool 并返回错误。
func (s *uploadSession) finish() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	err := s.up.Drain(ctx)
	s.cancel()
	runErr := <-s.done
	if err != nil {
		return err
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

// healthProtocol 仅在 lab-plan 已通过会话核验且组合绑定 1.1.0 时选择文件回放口径。
func healthProtocol(c config) (string, string) {
	if c.labSession != nil && len(c.labSession.Config.Inputs) > 0 && c.labSession.Manifest.ProtocolVersions["health"] == capturehealth.ReplayVersion {
		return capturehealth.ReplayVersion, "file_replay"
	}
	return capturehealth.Version, ""
}

func (s *uploadSession) healthObserver(c config) (*capturehealth.Observer, error) {
	window := time.Duration(c.Upload.HealthWindowMs) * time.Millisecond
	version, source := healthProtocol(c)
	return capturehealth.New(capturehealth.Identity{AssetID: c.AssetID, SensorID: c.SensorID, CaptureScopeID: c.CaptureScopeID, ConfigSha256: s.remote.ConfigHash, BuildSha256: s.build},
		capturehealth.Options{Version: version, Source: source, Window: window, Skew: s.up.Skew, QueueMax: s.up.QueueDepth, NewID: guardup.NewUUID, Emit: s.up.SubmitHealth,
			Memory: func() int64 {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				return int64(m.Sys)
			}})
}

func run() (runErr error) {
	cp := flag.String("config", "", "私有资产、接口白名单及截止授权")
	out := flag.String("out", "", "不存在的观察 JSONL")
	trace := flag.String("trace", "", "实时采集：不存在的私有头部轨迹；含端点，不能进 Git")
	replay := flag.String("replay", "", "复算既有同包轨迹，离线模式不开抓包")
	pcapPath := flag.String("pcap", "", "以 1 倍速只读回放冻结 PCAP/PCAPNG（research 或经会话准入的 lab），不注入报文")
	labPlan := flag.Bool("lab-plan", false, "按 lab.inputs 顺序回放同一会话的非重叠场景，共享固定偏移和 spool")
	startAt := flag.String("start", "", "-pcap 可选分区起点 RFC3339（原事件时间）")
	endAt := flag.String("end", "", "-pcap 可选分区终点 RFC3339（原事件时间）")
	captureAt := flag.String("capture-start", "", "-pcap 可选采集起点 RFC3339（原事件时间）：引擎与上下文覆盖从此起算，须不晚于首个报文")
	report := flag.String("report", "", "可选：不存在的去敏运行摘要")
	drain := flag.Bool("drain", false, "只续传 upload.spoolDir 中本 bootId 未确认的批次，不采集")
	drainTimeout := flag.Duration("drain-timeout", 60*time.Second, "结束时等待上传确认的上限")
	duration := flag.Duration("duration", 180*time.Second, "采集期限 1秒..30分钟")
	flag.Parse()
	modes := 0
	for _, v := range []bool{*trace != "", *replay != "", *pcapPath != "", *drain, *labPlan} {
		if v {
			modes++
		}
	}
	if *cp == "" || modes != 1 || (!*drain && *out == "") {
		return fmt.Errorf("须指定 config，trace、replay、pcap、lab-plan、drain 五选一；非 drain 模式须指定 out")
	}
	if (*startAt != "" || *endAt != "") && *pcapPath == "" && !*labPlan {
		return fmt.Errorf("start/end 只用于 -pcap")
	}
	c, err := loadConfig(*cp)
	if err != nil {
		return err
	}
	if *labPlan {
		if c.Lab == nil || len(c.Lab.Inputs) == 0 || c.Lab.Inputs[0].ScenarioID != c.Lab.ScenarioID {
			return guardlab.ErrAdmission
		}
		*pcapPath = c.Lab.Inputs[0].Path
	} else if c.Lab != nil && len(c.Lab.Inputs) > 0 && !*drain {
		return guardlab.ErrAdmission
	}
	if c.Lab != nil && *pcapPath == "" && !*drain {
		return guardlab.ErrAdmission
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if c.Lab != nil {
		if *startAt != "" || *endAt != "" || *captureAt != "" {
			return guardlab.ErrAdmission
		}
		c.labSession, err = prepareLab(c, *pcapPath)
		if err != nil {
			return err
		}
		watchDone := c.labSession.Watch(ctx, stop)
		defer func() { stop(); <-watchDone }()
	}
	summary := map[string]any{"status": "completed", "environment": c.Environment, "captureScope": c.CaptureScope, "automaticExecutionSupported": false}
	if c.labSession != nil {
		summary["lab"] = c.labSession.Summary()
	}
	if *report != "" {
		// 先确认路径可新建；摘要只在结束时写入，失败的运行不留下空摘要。
		if _, err := os.Lstat(*report); err == nil {
			return fmt.Errorf("report 已存在")
		}
	}
	writtenSummary := false
	writeSummary := func() error {
		writtenSummary = true
		if *report != "" {
			reportFile, err := create(*report)
			if err != nil {
				return err
			}
			defer reportFile.Close()
			en := json.NewEncoder(reportFile)
			en.SetIndent("", "  ")
			if err := en.Encode(summary); err != nil {
				return err
			}
			if err := reportFile.Sync(); err != nil {
				return err
			}
		}
		return json.NewEncoder(os.Stdout).Encode(summary)
	}
	defer func() {
		if c.labSession != nil && runErr != nil && !writtenSummary {
			summary["status"] = "failed"
			summary["errorCode"] = "LAB_RUN_FAILED"
			e := runErr
			if recorded := c.labSession.Error(); recorded != nil {
				e = recorded
			}
			for _, code := range []error{guardlab.ErrAdmission, guardlab.ErrMapping, guardlab.ErrLease, guardlab.ErrContinuity} {
				if errors.Is(e, code) {
					summary["errorCode"] = code.Error()
					break
				}
			}
			_ = writeSummary()
		}
	}()
	if *drain {
		s, err := startUpload(c, false, *drainTimeout)
		if err != nil {
			return err
		}
		if c.labSession != nil {
			go func() { <-ctx.Done(); s.cancel() }()
		}
		err = s.finish()
		summary["mode"], summary["upload"] = "drain", s.up.Stats()
		if err != nil {
			summary["status"] = "upload_incomplete"
			_ = writeSummary()
			return err
		}
		return writeSummary()
	}
	if (*replay != "" || *pcapPath != "") && c.Environment != "research" && !(c.labSession != nil && *pcapPath != "") {
		// lab 文件回放必须走显式会话/映射准入，不能仅改 environment 获得目标能力。
		return fmt.Errorf("文件回放只支持 research 环境")
	}
	if *replay != "" && c.Upload != nil {
		return fmt.Errorf("轨迹复算只写本地，不上传")
	}
	secret, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return fmt.Errorf("本机 HMAC 密钥不可读")
	}
	var upload *uploadSession
	if c.Upload != nil {
		if upload, err = startUpload(c, true, *drainTimeout); err != nil {
			return err
		}
		defer upload.cancel()
		if c.labSession != nil {
			go func() { <-ctx.Done(); upload.cancel() }()
		}
	}
	if c.labSession != nil {
		if err = c.labSession.OpenEvents(); err != nil {
			return err
		}
		defer func() {
			if e := c.labSession.CloseEvents(); runErr == nil && e != nil {
				runErr = e
			}
		}()
	}
	w, err := create(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	var emitted, skipped int64
	var clockSkew func() (int64, bool)
	if upload != nil {
		// 观察的 clockSkewMs 取上传心跳的新鲜实测值；过期或未测到即为 null，不填常数。
		clockSkew = upload.up.Skew
	}
	var emitMu sync.Mutex
	emitFor := func(lab *guardlab.Session) func(hostguard.Emission) error {
		return func(v hostguard.Emission) error {
			emitMu.Lock()
			defer emitMu.Unlock()
			if lab != nil {
				mapped, e := lab.MapEmission(v, time.Now())
				if e != nil {
					return e
				}
				v.Observation = mapped
			}
			if !inScope(c, v.Observation) {
				skipped++
				return nil
			}
			b, err := json.Marshal(v.Observation)
			if err != nil {
				return err
			}
			if _, err = w.Write(append(b, '\n')); err != nil {
				return err
			}
			emitted++
			if upload != nil {
				if err = upload.up.Submit(b); err != nil {
					return err
				}
			}
			if lab != nil {
				return lab.Event(v.Observation)
			}
			return nil
		}
	}
	engineConfig := hostguard.Config{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID,
		CaptureScopeID: c.CaptureScopeID, LocalAddresses: c.LocalAddresses, PeerSecret: secret, KeyEpoch: c.KeyEpoch,
		Environment: c.Environment, ClockSkew: clockSkew, Emit: emitFor(c.labSession)}
	if c.labSession != nil {
		engineConfig.Lease = c.labSession.Lease
		engineConfig.LocalAddresses = []netip.Addr{c.labSession.Local.OriginalLocal}
	}
	if c.LiveTargets != nil {
		lease, err := liveLease(c)
		if err != nil {
			return err
		}
		engineConfig.Lease = lease
	}
	e, err := hostguard.New(engineConfig)
	if err != nil {
		return err
	}
	var observer *capturehealth.Observer
	var observeErr error
	observe := func(s hostguard.LiveSample) {
		if observer != nil && observeErr == nil {
			observeErr = observer.Observe(s)
		}
	}
	if upload != nil {
		if observer, err = upload.healthObserver(c); err != nil {
			return err
		}
	}
	var lastSample hostguard.LiveSample
	switch {
	case *labPlan && c.labSession.Manifest.ContractVersion == guardlab.Version11:
		summary["mode"] = "lab_pcap_replay"
		replays, stats, sample, err := concurrentLabReplay(ctx, c.labSession, engineConfig, emitFor, observe)
		if err != nil {
			return err
		}
		summary["replays"] = replays
		e.Stats = stats
		lastSample = sample
	case *replay != "":
		summary["mode"] = "research_trace_replay"
		if err = replayTrace(*replay, e); err != nil {
			return err
		}
	case *pcapPath != "":
		summary["mode"] = "research_pcap_replay"
		var begin, end time.Time
		if *startAt != "" {
			if begin, err = time.Parse(time.RFC3339Nano, *startAt); err != nil {
				return fmt.Errorf("start 时间无效")
			}
		}
		if *endAt != "" {
			if end, err = time.Parse(time.RFC3339Nano, *endAt); err != nil {
				return fmt.Errorf("end 时间无效")
			}
		}
		if !begin.IsZero() && !end.IsZero() && !begin.Before(end) {
			return fmt.Errorf("分区范围无效")
		}
		var capture time.Time
		if *captureAt != "" {
			if capture, err = time.Parse(time.RFC3339Nano, *captureAt); err != nil {
				return fmt.Errorf("capture-start 时间无效")
			}
		}
		inputs := []guardlab.ReplayInput{{Path: *pcapPath}}
		if *labPlan {
			inputs = c.Lab.Inputs
		}
		var replays []map[string]any
		combined := map[string]int64{}
		var packets uint64
		var capacity, late int64
		for index, input := range inputs {
			if *labPlan {
				if err = c.labSession.SelectScenario(input.ScenarioID); err != nil {
					return err
				}
				if index > 0 {
					engineConfig.LocalAddresses = []netip.Addr{c.labSession.Local.OriginalLocal}
					e, err = hostguard.New(engineConfig)
					if err != nil {
						return err
					}
				}
			}
			options := hostguard.ReplayOptions{Start: begin, End: end, CaptureStart: capture, Observe: func(s hostguard.LiveSample) {
				s.PacketsSeen += packets
				s.CapacityDrops += capacity
				s.LateCount += late
				lastSample = s
				observe(s)
			}}
			if c.labSession != nil {
				summary["mode"] = "lab_pcap_replay"
				options.Start = c.labSession.CaptureStart()
				options.End = c.labSession.Scenario.SourceEnd
				options.CaptureStart = options.Start
				options.FixedOffset = &c.labSession.Offset
				options.Check = func() error {
					if !time.Now().Before(c.labSession.Manifest.ValidUntil) {
						return guardlab.ErrAdmission
					}
					return c.labSession.Error()
				}
			}
			res, err := hostguard.ReplayPCAP(ctx, input.Path, e, options)
			if err != nil {
				return fmt.Errorf("回放未完成: %w", err)
			}
			pcapHash, err := digest(input.Path)
			if err != nil {
				return err
			}
			if c.labSession != nil && pcapHash != c.labSession.Scenario.PCAPSHA256 {
				return guardlab.ErrMapping
			}
			// 原事件时间与墙钟分开：观察内事件时间 = 原时间 + timeOffsetMicros；emittedAt 为真实墙钟。
			summary["replay"] = map[string]any{"speed": 1, "timeOffsetMicros": res.Offset.Microseconds(), "sourceFirstPacketAt": res.SourceFirst, "sourceLastPacketAt": res.SourceLast,
				"wallStartedAt": res.WallStart, "wallFinishedAt": res.WallEnd, "packets": res.Packets, "maxLagMs": res.MaxLag.Milliseconds(), "pcapSha256": pcapHash, "partitionStart": *startAt, "partitionEnd": *endAt, "captureStart": *captureAt}
			replays = append(replays, summary["replay"].(map[string]any))
			if c.labSession != nil {
				replays[len(replays)-1]["scenarioId"] = c.labSession.Scenario.ScenarioID
			}
			for k, v := range e.Stats {
				combined[k] += v
			}
			packets = lastSample.PacketsSeen
			capacity = lastSample.CapacityDrops
			late = lastSample.LateCount
		}
		if *labPlan {
			summary["replays"] = replays
			delete(summary, "replay")
			e.Stats = combined
		}
	default:
		summary["mode"] = "live"
		if *duration < time.Second || *duration > 30*time.Minute || time.Now().Add(*duration).After(c.AuthorizedUntil) {
			return fmt.Errorf("采集时限超出授权")
		}
		t, err := create(*trace)
		if err != nil {
			return err
		}
		defer t.Close()
		te := json.NewEncoder(t)
		cctx, cancel := context.WithTimeout(ctx, *duration)
		defer cancel()
		var check func() error
		if upload != nil {
			check = upload.up.Err
		}
		if err = capture(cctx, c, e, te.Encode, observer, check); err != nil {
			// 读取异常的尾窗已标记缺口，先尝试送达；上传失败仍保留两端错误，不返回成功。
			if upload != nil {
				err = errors.Join(err, upload.finish())
			}
			return err
		}
		if err = t.Sync(); err != nil {
			return err
		}
	}
	if observer != nil && observeErr == nil && !lastSample.At.IsZero() {
		observeErr = observer.Finish(lastSample)
	}
	if observeErr != nil {
		return observeErr
	}
	if err = w.Sync(); err != nil {
		return err
	}
	summary["stats"], summary["emitted"], summary["outOfScopeSkipped"] = e.Stats, emitted, skipped
	if observer != nil {
		summary["observerSessionId"] = observer.Session()
	}
	if h, err := digest(*out); err == nil {
		summary["observationsSha256"] = h
	}
	if h, err := digest(*cp); err == nil {
		summary["configSha256"] = h
	}
	if upload != nil {
		err = upload.finish()
		summary["upload"] = upload.up.Stats()
		if err != nil {
			summary["status"] = "upload_incomplete"
			_ = writeSummary()
			return fmt.Errorf("%w；spool 已保留，可用 -drain 续传", err)
		}
	}
	return writeSummary()
}

func replayTrace(path string, e *hostguard.Engine) error {
	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	closed := false
	for {
		var v hostguard.LiveEvent
		err := d.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if closed {
			return fmt.Errorf("close 后仍有轨迹")
		}
		if err = e.ApplyLiveEvent(v); err != nil {
			return err
		}
		closed = v.Kind == "close"
	}
	if !closed {
		return fmt.Errorf("轨迹未完整关闭")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardlive:", err)
		os.Exit(1)
	}
}
