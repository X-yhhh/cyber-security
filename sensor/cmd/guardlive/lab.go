package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/guardlab"
	"github.com/xyh/cyber-security/sensor/internal/guardup"
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
		return nil, e
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
			if !previous.IsZero() && s.Scenario.SourceStart.Before(previous) {
				return nil, guardlab.ErrMapping
			}
			previous = s.Scenario.SourceEnd
			if e = s.Preflight(input.Path); e != nil {
				return nil, e
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
		if !time.Now().Before(s.Manifest.Time.WarmupStart.Add(s.Offset)) {
			return nil, guardlab.ErrAdmission
		}
	}
	return s, nil
}
