// Command g2fixtures 生成 G2 包级对拍 fixtures（不联网、不打开网卡）。
//
//	g2fixtures -dir <输出目录>                                         合成场景
//	g2fixtures -dir <输出目录> -pcap anon.pcap -local-addr ... -subnet ...   已有 pcap（真实流量须先假名化）
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
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

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

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	dir := flag.String("dir", "", "输出目录")
	in := flag.String("pcap", "", "可选：已有 pcap；给出时按它生成，否则生成合成场景")
	var locals, subnets multi
	flag.Var(&locals, "local-addr", "本机地址（-pcap 模式，可重复）")
	flag.Var(&subnets, "subnet", "本机 IPv4 子网（-pcap 模式，可重复）")
	flag.Parse()
	var err error
	switch {
	case *dir == "":
		err = errors.New("须提供 -dir")
	case *in == "":
		err = Generate(*dir)
	default:
		err = GenerateFromPcap(*dir, *in, locals, subnets)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "g2fixtures:", err)
		os.Exit(1)
	}
}

// Generate 把合成场景 fixtures 写到 dir。
func Generate(dir string) error {
	var pcap bytes.Buffer
	if err := synth.WritePcap(&pcap, synth.G2SnapLen, synth.G2Frames()); err != nil {
		return err
	}
	return write(dir, pcap.Bytes(), fixture{
		Contract:   spec.ContractVersion,
		Purpose:    "包 → 流 → 特征 的 Go/Java 独立实现对拍（G2）；只验证实现一致性，不代表真实流量分布",
		LocalAddrs: []string{synth.G2Host.String(), synth.G2HostV6.String()},
		Subnets:    []string{synth.G2Subnet.String()},
		MTU:        1500, SnapLen: synth.G2SnapLen, KeyBase: "g2",
		Addressing: "RFC 5737 / RFC 3849 文档保留地址，载荷全零，合成生成",
		Coverage:   synth.G2Coverage,
	})
}

// GenerateFromPcap 以已有 pcap 生成 fixtures。真实流量必须先经 pcapanon 假名化再入库。
func GenerateFromPcap(dir, path string, locals, subnets []string) error {
	if len(locals) == 0 {
		return errors.New("-pcap 模式须提供至少一个 -local-addr")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return write(dir, raw, fixture{
		Contract:   spec.ContractVersion,
		Purpose:    "本机 en0 真实流量（假名化）的 Go/Java 对拍（G2，路线 B §12.3）；不代表其他主机的流量分布",
		LocalAddrs: locals, Subnets: subnets, MTU: 1500, SnapLen: spec.SnapLen, KeyBase: "g2real",
		Addressing: "按 sensor/internal/anon 假名化：文档保留地址、只保留到传输层头部、时间平移；映射表未保存",
		Coverage:   []string{"real_en0_capture"},
	})
}

func write(dir string, pcap []byte, fx fixture) error {
	opt := extract.Options{KeyBase: fx.KeyBase, MTU: fx.MTU}
	for _, s := range fx.LocalAddrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("本机地址无效: %s", s)
		}
		opt.LocalAddrs = append(opt.LocalAddrs, a.Unmap())
	}
	for _, s := range fx.Subnets {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("子网无效: %s", s)
		}
		opt.Subnets = append(opt.Subnets, p)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	pcapPath := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(pcapPath, pcap, 0o644); err != nil {
		return err
	}
	var records bytes.Buffer
	diag, err := extract.Run(pcapPath, &records, opt)
	if err != nil {
		return err
	}
	fx.Frames = int(diag.Frames)
	fxJSON, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	diagJSON, err := extract.DiagnosticsJSON(diag)
	if err != nil {
		return err
	}
	out := map[string][]byte{"fixture.json": append(fxJSON, '\n'), "expected-records.jsonl": records.Bytes(),
		"expected-diagnostics.json": diagJSON}
	sums := map[string]string{}
	for _, name := range Files {
		b, ok := out[name]
		if !ok {
			b = pcap
		} else if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sums[name] = hex.EncodeToString(h[:])
	}
	raw, err := json.MarshalIndent(sums, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "checksums.json"), append(raw, '\n'), 0o644)
}
