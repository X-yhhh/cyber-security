// Package agent 串起 凭据 → 后端配置校验 → 抓包流水线 → 批次上报 → 心跳与健康窗口。
//
// 本地配置只含标识与白名单，不含凭据；凭据只从操作系统密钥库读取。后端配置只能收窄本地授权范围：
// 接口必须在本地白名单内，过滤策略只接受固定表达式，采样策略必须为空（采样会改变特征口径），
// 契约版本必须等于本二进制内置的 v4 契约。任一不满足即 fail-closed，不开始抓包。
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"

	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/spec"
	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

// LocalConfig 是本机配置文件（JSON）。不得包含凭据或口令字段。
type LocalConfig struct {
	BaseURL              string   `json:"baseUrl"`
	SensorID             int64    `json:"sensorId"`
	DataSourceID         int64    `json:"dataSourceId"`
	SourceMappingVersion string   `json:"sourceMappingVersion"`
	StateDir             string   `json:"stateDir"`
	AllowedInterfaces    []string `json:"allowedInterfaces"`
	KeystoreService      string   `json:"keystoreService"`
	KeystoreAccount      string   `json:"keystoreAccount"`
	MTU                  int      `json:"mtu"`
	MaxFlows             int      `json:"maxFlows"`
	SpoolBatches         int      `json:"spoolBatches"`
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// LoadLocalConfig 读取并校验本机配置；未知字段拒绝，避免误把凭据写进配置文件后被静默忽略。
func LoadLocalConfig(path string) (LocalConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return LocalConfig{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var c LocalConfig
	if err := dec.Decode(&c); err != nil {
		return LocalConfig{}, fmt.Errorf("本机配置无法解析: %w", err)
	}
	if c.MTU == 0 {
		c.MTU = 1500
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 200_000
	}
	if c.SpoolBatches == 0 {
		c.SpoolBatches = 64
	}
	switch {
	case c.SensorID < 1 || c.DataSourceID < 1:
		return c, errors.New("sensorId 与 dataSourceId 必须为正整数")
	case !safeVersion.MatchString(c.SourceMappingVersion):
		return c, errors.New("sourceMappingVersion 格式无效")
	case c.StateDir == "":
		return c, errors.New("stateDir 不能为空")
	case c.KeystoreService == "" || c.KeystoreAccount == "":
		return c, errors.New("须声明密钥库服务名与账户名")
	case c.MTU < 576 || c.MTU > 9216 || c.MaxFlows < 1 || c.SpoolBatches < 1:
		return c, errors.New("mtu、maxFlows 或 spoolBatches 超出允许范围")
	}
	return c, nil
}

// RemoteDecision 是后端配置校验的结论。
type RemoteDecision struct {
	ConfigVersion string
	Interface     string // 实时模式下选定的接口；文件模式为空
}

// ErrConfigRejected 表示后端配置超出本地授权或契约，传感器拒绝运行。
var ErrConfigRejected = errors.New("后端配置不被本传感器接受")

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfigRejected, fmt.Sprintf(format, args...))
}

// ValidateRemote 校验后端下发的已批准配置。live=true 时要求 interfaceScope 恰好声明一个本地白名单内的接口。
func ValidateRemote(cfg uplink.Config, local LocalConfig, live bool) (RemoteDecision, error) {
	if !safeVersion.MatchString(cfg.ConfigVersion) {
		return RemoteDecision{}, reject("configVersion 格式无效")
	}
	if cfg.FeatureContractVersion != spec.ContractVersion {
		return RemoteDecision{}, reject("契约版本 %q 不是本传感器实现的 %s", cfg.FeatureContractVersion, spec.ContractVersion)
	}
	var filter map[string]any
	if err := json.Unmarshal([]byte(orEmpty(cfg.FilterPolicy)), &filter); err != nil {
		return RemoteDecision{}, reject("filterPolicy 不是 JSON 对象")
	}
	if expr, ok := filter["bpf"]; len(filter) > 1 || (len(filter) == 1 && (!ok || expr != capture.FixedFilter)) {
		return RemoteDecision{}, reject("filterPolicy 只接受空对象或 {\"bpf\":%q}", capture.FixedFilter)
	}
	var sampling map[string]any
	if err := json.Unmarshal([]byte(orEmpty(cfg.SamplingPolicy)), &sampling); err != nil || len(sampling) != 0 {
		return RemoteDecision{}, reject("samplingPolicy 必须为空对象：采样会改变特征口径")
	}
	d := RemoteDecision{ConfigVersion: cfg.ConfigVersion}
	if !live {
		return d, nil
	}
	var scope struct {
		Interfaces []string `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(orEmpty(cfg.InterfaceScope)), &scope); err != nil || len(scope.Interfaces) != 1 {
		return RemoteDecision{}, reject("interfaceScope 须恰好声明一个接口")
	}
	if !slices.Contains(local.AllowedInterfaces, scope.Interfaces[0]) {
		return RemoteDecision{}, reject("接口 %q 不在本机授权白名单内", scope.Interfaces[0])
	}
	d.Interface = scope.Interfaces[0]
	return d, nil
}

func orEmpty(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
