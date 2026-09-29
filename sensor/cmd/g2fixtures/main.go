// Command g2fixtures 生成 G2 包级对拍 fixtures（不联网、不打开网卡）。
//
//	g2fixtures -dir <输出目录>
//
// 一次输出 capture.pcap、fixture.json、expected-records.jsonl、expected-diagnostics.json 与 checksums.json。
// 期望记录由 internal/extract（即 `sensor extract` 的同一实现）计算；Java 参考实现（backend ingest.packet）
// 读取同一 pcap 独立计算后逐字段比对。修改流表或特征构造后重新运行本命令并提交结果。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/xyh/cyber-security/sensor/internal/extract"
	"github.com/xyh/cyber-security/sensor/internal/spec"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

type fixture struct {
	Contract   string   `json:"contract"`
	Purpose    string   `json:"purpose"`
	LocalAddrs []string `json:"localAddrs"`
	Subnets    []string `json:"subnets"`
	MTU        int      `json:"mtu"`
	SnapLen    int      `json:"snapLen"`
	KeyBase    string   `json:"keyBase"`
	Frames     int      `json:"frames"`
	Addressing string   `json:"addressing"`
	Coverage   []string `json:"coverage"`
}

// Files 是生成的文件名（checksums.json 除外），顺序固定。
var Files = []string{"capture.pcap", "fixture.json", "expected-records.jsonl", "expected-diagnostics.json"}

func main() {
	dir := flag.String("dir", "", "输出目录")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "g2fixtures: 须提供 -dir")
		os.Exit(2)
	}
	if err := Generate(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "g2fixtures:", err)
		os.Exit(1)
	}
}

// Generate 把全部 fixtures 写到 dir。
func Generate(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	frames := synth.G2Frames()
	var pcap bytes.Buffer
	if err := synth.WritePcap(&pcap, synth.G2SnapLen, frames); err != nil {
		return err
	}
	pcapPath := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(pcapPath, pcap.Bytes(), 0o644); err != nil {
		return err
	}
	fx := fixture{
		Contract:   spec.ContractVersion,
		Purpose:    "包 → 流 → 特征 的 Go/Java 独立实现对拍（G2）；只验证实现一致性，不代表真实流量分布",
		LocalAddrs: []string{synth.G2Host.String(), synth.G2HostV6.String()},
		Subnets:    []string{synth.G2Subnet.String()},
		MTU:        1500, SnapLen: synth.G2SnapLen, KeyBase: "g2", Frames: len(frames),
		Addressing: "RFC 5737 / RFC 3849 文档保留地址，载荷全零，合成生成",
		Coverage:   synth.G2Coverage,
	}
	raw, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	var records bytes.Buffer
	diag, err := extract.Run(pcapPath, &records, extract.Options{
		LocalAddrs: []netip.Addr{synth.G2Host, synth.G2HostV6}, Subnets: []netip.Prefix{synth.G2Subnet},
		KeyBase: fx.KeyBase, MTU: fx.MTU})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-records.jsonl"), records.Bytes(), 0o644); err != nil {
		return err
	}
	diagJSON, err := extract.DiagnosticsJSON(diag)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-diagnostics.json"), diagJSON, 0o644); err != nil {
		return err
	}
	sums := map[string]string{}
	for _, name := range Files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sums[name] = hex.EncodeToString(h[:])
	}
	raw, err = json.MarshalIndent(sums, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "checksums.json"), append(raw, '\n'), 0o644)
}
