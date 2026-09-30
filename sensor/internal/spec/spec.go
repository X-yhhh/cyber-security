// Package spec 固定特征契约 unsw-nb15-flow-v4 的计算常量（docs/特征规格-unsw-nb15-flow-v4.md）。
//
// 这里的值必须与后端 classpath:feature-contract/unsw-nb15-flow-v4.json 一致；spec_test.go 逐项对拍，
// 契约文件变化而本包未同步时测试失败。本包不读取配置：契约参数不能由运行时配置放宽。
package spec

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"
)

const (
	ContractVersion = "unsw-nb15-flow-v4"
	DirectionBasis  = "initiator_to_responder"

	// §3 窗口：每个传感器、每个地址族最近 100 条已完成流，含当前流自身。
	WindowSize = 100

	// §1.1 封流参数。
	TCPIdle     = 60 * time.Second
	OtherIdle   = 30 * time.Second
	MaxLifetime = 60 * time.Second
	// FIN/RST 导出后吸收尾随报文的时长。
	Tombstone = 5 * time.Second
	// §1.3 孤立后续分片的等待时长。
	FragmentWait = 30 * time.Second
	// §3 重排序：flowEndAt ≤ now − (TCP 空闲超时 + 1 s) 的记录才释放。
	ReorderDelay = TCPIdle + time.Second

	// §1 snaplen 128 字节，只含头部，不读载荷（D8）。
	SnapLen = 128
)

// NumericFields 是 ONNX flow_numeric 的列顺序（§2.1）。
var NumericFields = []string{
	"dur", "sbytes", "dbytes", "sload", "dload", "tcprtt", "ackdat", "synack", "smean", "dmean",
	"spkts", "dpkts", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
}

// CategoricalFields 按契约顺序。
var CategoricalFields = []string{"proto", "service"}

// servicePorts 是 §2.3 冻结的端口映射，键为 "协议/responder 端口"。
var servicePorts = map[string]string{
	"udp/67": "dhcp", "udp/68": "dhcp",
	"tcp/53": "dns", "udp/53": "dns",
	"tcp/21": "ftp", "tcp/20": "ftp-data",
	"tcp/80": "http", "tcp/8080": "http",
	"tcp/6667": "irc", "tcp/110": "pop3",
	"udp/1812": "radius", "udp/1813": "radius",
	"tcp/25":  "smtp",
	"udp/161": "snmp", "udp/162": "snmp",
	"tcp/22": "ssh", "tcp/443": "ssl",
}

// Service 按 responder 端口与协议查 §2.3 映射；未命中或非 TCP/UDP 取 "-"。不读载荷。
func Service(protoNumber uint8, responderPort uint16) string {
	var p string
	switch protoNumber {
	case 6:
		p = "tcp"
	case 17:
		p = "udp"
	default:
		return "-"
	}
	if s, ok := servicePorts[fmt.Sprintf("%s/%d", p, responderPort)]; ok {
		return s
	}
	return "-"
}

//go:embed iana-protocol-numbers.json
var protocolTableJSON []byte

type protocolTable struct {
	Name    string            `json:"name"`
	Entries map[string]string `json:"entries"`
}

var protoNames = mustLoadProtocols()

func mustLoadProtocols() map[uint8]string {
	var t protocolTable
	if err := json.Unmarshal(protocolTableJSON, &t); err != nil || t.Name != "iana-protocol-numbers" || len(t.Entries) == 0 {
		panic("内嵌的 IANA 协议表无效")
	}
	out := make(map[uint8]string, len(t.Entries))
	for k, v := range t.Entries {
		var n int
		if _, err := fmt.Sscanf(k, "%d", &n); err != nil || n < 0 || n > 255 || fmt.Sprint(n) != k {
			panic("内嵌的 IANA 协议表含非法协议号")
		}
		out[uint8(n)] = v
	}
	return out
}

// Proto 返回 §2.2 的 proto 取值：IANA 关键字小写；表中没有的协议号记 proto-<号>。
func Proto(protoNumber uint8) string {
	if s, ok := protoNames[protoNumber]; ok {
		return s
	}
	return fmt.Sprintf("proto-%d", protoNumber)
}

// Idle 返回协议对应的空闲超时。
func Idle(protoNumber uint8) time.Duration {
	if protoNumber == 6 {
		return TCPIdle
	}
	return OtherIdle
}
