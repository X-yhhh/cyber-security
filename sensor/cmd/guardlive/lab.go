package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/guardlab"
	"github.com/xyh/cyber-security/sensor/internal/guardup"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// prepareLab 不启动上传或捕获；先核验会话和私有签名映射，失败不会留下可发送批次。
func prepareLab(c config, pcap string) (*guardlab.Session, error) {
	if c.Lab == nil || c.Upload == nil || c.Environment != "lab" {
		return nil, guardlab.ErrAdmission
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, guardlab.ErrAdmission
	}
	build, e := digest(exe)
	if e != nil {
		return nil, guardlab.ErrAdmission
	}
	secret, e := guardlab.ReadPrivate(c.SecretFile)
	if e != nil {
		return nil, e
	}
	u := c.Upload
	client, e := guardup.NewClient(guardup.ClientConfig{BaseURL: u.BaseURL, SensorID: c.SensorID, CAFile: u.CAFile, CertificateFile: u.CertificateFile, KeyFile: u.KeyFile, CredentialFile: u.CredentialFile})
	if e != nil {
		return nil, guardlab.ErrAdmission
	}
	leaser, e := guardlab.NewTargetClient(c.Lab.Targets)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, e := guardlab.Open(ctx, *c.Lab, guardlab.Identity{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID, CaptureScopeID: c.CaptureScopeID, BuildSHA256: build, KeyEpoch: c.KeyEpoch, LocalAddresses: c.LocalAddresses, PeerSecret: secret}, client, leaser, time.Now())
	if e != nil {
		return nil, fmt.Errorf("lab admission: %w", e)
	}
	if pcap != "" {
		inputs := []guardlab.ReplayInput{{ScenarioID: s.Config.ScenarioID, Path: pcap}}
		if len(s.Config.Inputs) > 0 {
			inputs = s.Config.Inputs
		}
		seen := map[string]bool{}
		var previous time.Time
		for _, input := range inputs {
			if seen[input.ScenarioID] || !filepath.IsAbs(input.Path) {
				return nil, guardlab.ErrMapping
			}
			seen[input.ScenarioID] = true
			if e = s.SelectScenario(input.ScenarioID); e != nil {
				return nil, e
			}
			if s.Manifest.ContractVersion == guardlab.Version10 && !previous.IsZero() && s.Scenario.SourceStart.Before(previous) {
				return nil, guardlab.ErrMapping
			}
			previous = s.Scenario.SourceEnd
			if e = s.Preflight(input.Path); e != nil {
				return nil, fmt.Errorf("lab preflight scenario %s: %w", input.ScenarioID, e)
			}
			if c.CaptureScope == scopeAllInbound && s.Local.Direction != "inbound" {
				return nil, guardlab.ErrMapping
			}
			if c.CaptureScope == scopeService {
				found := false
				for _, p := range c.PeerAddresses {
					found = found || p == s.Local.OriginalPeer
				}
				if c.ServicePort != s.Local.ServicePort || !found {
					return nil, guardlab.ErrMapping
				}
			}
		}
		if e = s.SelectScenario(s.Config.ScenarioID); e != nil {
			return nil, e
		}
		if !time.Now().Before(s.CaptureStart().Add(s.Offset)) {
			return nil, guardlab.ErrAdmission
		}
	}
	return s, nil
}

// concurrentLabReplay 为每段创建独立因果引擎，按已签名的绝对时间并发等待。
// 上传、事件写入集中串行化；健康样本由独立节拍汇总，回放协程不在聚合锁内调用观察器。
// 场景之间不混合主机上下文或连接 ID。
func concurrentLabReplay(ctx context.Context, parent *guardlab.Session, base hostguard.Config,
	emitFor func(*guardlab.Session) func(hostguard.Emission) error, observe func(hostguard.LiveSample)) ([]map[string]any, map[string]int64, hostguard.LiveSample, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	inputs := parent.Config.Inputs
	replays := make([]map[string]any, len(inputs))
	stats := map[string]int64{}
	samples := make([]hostguard.LiveSample, len(inputs))
	completed := make([]bool, len(inputs))
	for i := range samples {
		samples[i].At = time.Now()
	}
	var first error
	var mu sync.Mutex
	var wg sync.WaitGroup
	for index, input := range inputs {
		child, err := parent.ForkScenario(input.ScenarioID)
		if err != nil {
			cancel()
			wg.Wait()
			return nil, nil, hostguard.LiveSample{}, err
		}
		cfg := base
		cfg.LocalAddresses = []netip.Addr{child.Local.OriginalLocal}
		cfg.Lease = child.Lease
		cfg.Emit = emitFor(child)
		engine, err := hostguard.New(cfg)
		if err != nil {
			cancel()
			wg.Wait()
			return nil, nil, hostguard.LiveSample{}, err
		}
		wg.Add(1)
		go func(index int, input guardlab.ReplayInput, child *guardlab.Session, engine *hostguard.Engine) {
			defer wg.Done()
			result, err := hostguard.ReplayPCAP(ctx, input.Path, engine, hostguard.ReplayOptions{
				Start: child.CaptureStart(), End: child.Scenario.SourceEnd, CaptureStart: child.CaptureStart(), FixedOffset: &child.Offset,
				Check: func() error {
					if !time.Now().Before(child.Manifest.ValidUntil) {
						return guardlab.ErrAdmission
					}
					return parent.Error()
				},
				Observe: func(sample hostguard.LiveSample) {
					mu.Lock()
					// 汇总节拍之前到达的缺口必须锁存，不能被紧随其后的正常样本覆盖。
					sample.Gap = sample.Gap || samples[index].Gap
					samples[index] = sample
					mu.Unlock()
				},
			})
			mu.Lock()
			completed[index] = true
			mu.Unlock()
			if err == nil {
				var sum string
				sum, err = digest(input.Path)
				if err == nil && sum != child.Scenario.PCAPSHA256 {
					err = guardlab.ErrMapping
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = fmt.Errorf("lab scenario %s: %w", input.ScenarioID, err)
					cancel()
				}
				return
			}
			replays[index] = map[string]any{"scenarioId": input.ScenarioID, "speed": 1, "timeOffsetMicros": result.Offset.Microseconds(),
				"sourceFirstPacketAt": result.SourceFirst, "sourceLastPacketAt": result.SourceLast, "wallStartedAt": result.WallStart,
				"wallFinishedAt": result.WallEnd, "packets": result.Packets, "maxLagMs": result.MaxLag.Milliseconds(),
				"pcapSha256": child.Scenario.PCAPSHA256, "captureStart": child.CaptureStart()}
			for k, v := range engine.Stats {
				stats[k] += v
			}
		}(index, input, child, engine)
	}
	stopHealth := make(chan struct{})
	healthDone := make(chan hostguard.LiveSample, 1)
	go func() {
		healthDone <- sampleLabHealth(stopHealth, 100*time.Millisecond, &mu, samples, completed, observe)
	}()
	wg.Wait()
	close(stopHealth)
	last := <-healthDone
	return replays, stats, last, first
}

// sampleLabHealth 是唯一调用观察器的协程；每次取一致的累计快照后立即释放槽位锁。
// 停止时补采最终计数，单段样本超过上限仍由 aggregateLabHealth 显式标记缺口。
func sampleLabHealth(stop <-chan struct{}, interval time.Duration, mu *sync.Mutex,
	samples []hostguard.LiveSample, completed []bool, observe func(hostguard.LiveSample)) hostguard.LiveSample {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	snapshot := func() hostguard.LiveSample {
		mu.Lock()
		defer mu.Unlock()
		total := aggregateLabHealth(samples, completed, time.Now())
		for i := range samples {
			samples[i].Gap = false
		}
		return total
	}
	for {
		select {
		case <-ticker.C:
			observe(snapshot())
		case <-stop:
			last := snapshot()
			observe(last)
			return last
		}
	}
}

// aggregateLabHealth 保留已完成场景的累计计数；仍在回放的场景独立检查样本停顿。
// 调用方持有聚合锁，其他场景持续送样本也不能掩盖单个场景超过 5 秒的缺口。
func aggregateLabHealth(samples []hostguard.LiveSample, completed []bool, now time.Time) hostguard.LiveSample {
	total := hostguard.LiveSample{At: now}
	for i, sample := range samples {
		total.PacketsSeen += sample.PacketsSeen
		total.CapacityDrops += sample.CapacityDrops
		total.LateCount += sample.LateCount
		total.Gap = total.Gap || sample.Gap || !completed[i] && now.Sub(sample.At) > capturehealth.MaxWindow
	}
	return total
}
