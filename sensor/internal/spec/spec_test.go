package spec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 仓库内后端契约与共享表的位置（相对本包目录）。
var backendResources = filepath.Join("..", "..", "..", "backend", "src", "main", "resources", "feature-contract")

func TestProtocolTableMatchesBackendCopy(t *testing.T) {
	backend, err := os.ReadFile(filepath.Join(backendResources, "tables", "iana-protocol-numbers.json"))
	if err != nil {
		t.Fatalf("读取后端协议表失败: %v", err)
	}
	if !bytes.Equal(backend, protocolTableJSON) {
		t.Fatal("传感器内嵌协议表与后端共享表不一致；请从后端复制同一文件")
	}
}

func TestContractConstantsMatchBackendContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(backendResources, ContractVersion+".json"))
	if err != nil {
		t.Fatalf("读取后端契约失败: %v", err)
	}
	var c struct {
		Version        string `json:"version"`
		DirectionBasis string `json:"directionBasis"`
		Window         struct {
			Size int `json:"size"`
		} `json:"window"`
		RawClosure    map[string]int `json:"flowClosure"`
		NumericFields []struct {
			Name string `json:"name"`
		} `json:"numericFields"`
		CategoricalFields []struct {
			Name string `json:"name"`
		} `json:"categoricalFields"`
		ServiceRules struct {
			PortMap map[string]string `json:"portMap"`
			Default string            `json:"default"`
		} `json:"serviceRules"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != ContractVersion || c.DirectionBasis != DirectionBasis || c.Window.Size != WindowSize {
		t.Fatalf("契约版本/方向/窗口不一致: %s %s %d", c.Version, c.DirectionBasis, c.Window.Size)
	}
	want := map[string]int{"tcpIdleSeconds": int(TCPIdle.Seconds()), "udpIdleSeconds": int(OtherIdle.Seconds()),
		"otherIdleSeconds": int(OtherIdle.Seconds()), "maxLifetimeSeconds": int(MaxLifetime.Seconds())}
	for k, v := range want {
		if c.RawClosure[k] != v {
			t.Fatalf("封流参数 %s: 契约 %d，传感器 %d", k, c.RawClosure[k], v)
		}
	}
	if len(c.NumericFields) != len(NumericFields) {
		t.Fatalf("数值字段数不一致: %d vs %d", len(c.NumericFields), len(NumericFields))
	}
	for i, f := range c.NumericFields {
		if f.Name != NumericFields[i] {
			t.Fatalf("数值字段 #%d: 契约 %s，传感器 %s", i, f.Name, NumericFields[i])
		}
	}
	for i, f := range c.CategoricalFields {
		if f.Name != CategoricalFields[i] {
			t.Fatalf("类别字段 #%d 不一致", i)
		}
	}
	if len(c.ServiceRules.PortMap) != len(servicePorts) || c.ServiceRules.Default != "-" {
		t.Fatalf("service 映射条数或默认值不一致")
	}
	for k, v := range c.ServiceRules.PortMap {
		if servicePorts[k] != v {
			t.Fatalf("service 映射 %s: 契约 %s，传感器 %s", k, v, servicePorts[k])
		}
	}
}

func TestServiceAndProto(t *testing.T) {
	cases := []struct {
		proto uint8
		port  uint16
		want  string
	}{
		{6, 443, "ssl"}, {17, 443, "-"}, {6, 8080, "http"}, {17, 53, "dns"}, {6, 20, "ftp-data"},
		{1, 0, "-"}, {6, 12345, "-"}, {132, 80, "-"},
	}
	for _, c := range cases {
		if got := Service(c.proto, c.port); got != c.want {
			t.Errorf("Service(%d,%d)=%s want %s", c.proto, c.port, got, c.want)
		}
	}
	for n, want := range map[uint8]string{6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp", 13: "argus", 253: "proto-253", 255: "proto-255"} {
		if got := Proto(n); got != want {
			t.Errorf("Proto(%d)=%s want %s", n, got, want)
		}
	}
}
