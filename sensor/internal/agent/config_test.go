package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

func local() LocalConfig {
	return LocalConfig{SensorID: 1, DataSourceID: 2, SourceMappingVersion: "m1", StateDir: "x",
		AllowedInterfaces: []string{"en0"}, KeystoreService: "svc", KeystoreAccount: "acct"}
}

func remote(scope, filter, sampling string) uplink.Config {
	return uplink.Config{ConfigVersion: "cfg-1", FeatureContractVersion: "unsw-nb15-flow-v4",
		InterfaceScope: scope, FilterPolicy: filter, SamplingPolicy: sampling}
}

func TestValidateRemote(t *testing.T) {
	ok := []struct {
		cfg  uplink.Config
		live bool
	}{
		{remote(`{"interfaces":["en0"]}`, `{}`, `{}`), true},
		{remote(`{"interfaces":["en0"]}`, `{"bpf":"ip or ip6"}`, ``), true},
		{remote(`{"replay":"x"}`, ``, `{}`), false},
	}
	for _, c := range ok {
		d, err := ValidateRemote(c.cfg, local(), c.live)
		if err != nil {
			t.Fatalf("应接受 %+v: %v", c.cfg, err)
		}
		if c.live && d.Interface != "en0" {
			t.Fatalf("应选定 en0: %+v", d)
		}
	}
	bad := []struct {
		cfg  uplink.Config
		live bool
	}{
		{remote(`{"interfaces":["en1"]}`, `{}`, `{}`), true},
		{remote(`{"interfaces":["en0","en1"]}`, `{}`, `{}`), true},
		{remote(`{}`, `{}`, `{}`), true},
		{remote(`{"interfaces":["en0"]}`, `{"bpf":"tcp port 22"}`, `{}`), true},
		{remote(`{"interfaces":["en0"]}`, `{}`, `{"rate":0.1}`), true},
		{remote(`{"interfaces":["en0"]}`, `not-json`, `{}`), true},
	}
	for _, c := range bad {
		if _, err := ValidateRemote(c.cfg, local(), c.live); !errors.Is(err, ErrConfigRejected) {
			t.Fatalf("应拒绝 %+v: %v", c.cfg, err)
		}
	}
	v31 := remote(`{"interfaces":["en0"]}`, `{}`, `{}`)
	v31.FeatureContractVersion = "unsw-nb15-flow-v3.1"
	if _, err := ValidateRemote(v31, local(), true); !errors.Is(err, ErrConfigRejected) {
		t.Fatal("非 v4 契约应拒绝")
	}
}

func TestLoadLocalConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor.json")
	os.WriteFile(path, []byte(`{"sensorId":1,"dataSourceId":2,"sourceMappingVersion":"m1","stateDir":"s",
		"keystoreService":"svc","keystoreAccount":"a","credential":"mch_1.x"}`), 0o600)
	if _, err := LoadLocalConfig(path); err == nil {
		t.Fatal("含未知字段（如凭据）的本机配置应拒绝")
	}
	os.WriteFile(path, []byte(`{"sensorId":1,"dataSourceId":2,"sourceMappingVersion":"m1","stateDir":"s",
		"keystoreService":"svc","keystoreAccount":"a"}`), 0o600)
	c, err := LoadLocalConfig(path)
	if err != nil || c.MTU != 1500 || c.SpoolBatches != 64 {
		t.Fatalf("默认值错误: %+v %v", c, err)
	}
}

func TestStateAllocatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	for want := int64(0); want < 3; want++ {
		if got, err := s.Allocate("cfg-1"); err != nil || got != want {
			t.Fatalf("序号错误: %d %v", got, err)
		}
	}
	if got, _ := s.Allocate("cfg-2"); got != 0 {
		t.Fatal("不同配置版本应独立计数")
	}
	info, _ := os.Stat(filepath.Join(dir, "state.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("状态文件权限应为 0600: %v", info.Mode())
	}
	s2, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Allocate("cfg-1"); got != 3 {
		t.Fatalf("重启后不应复用序号: %d", got)
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{bad"), 0o600)
	if _, err := LoadState(dir); err == nil {
		t.Fatal("损坏的状态文件应拒绝")
	}
}
