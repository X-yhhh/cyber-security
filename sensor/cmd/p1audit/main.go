// p1audit 只读核验完整公开 PCAP 与 Zeek 标签；输出去敏审计，不产生 v5 模型输入。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"

	"github.com/xyh/cyber-security/sensor/internal/probe"
)

func run() error {
	pcap := flag.String("pcap", "", "完整原始 PCAP")
	labels := flag.String("labels", "", "对应 Zeek conn.log.labeled")
	scenario := flag.String("scenario", "", "公开场景 ID")
	anchor := flag.String("local-addr", "", "发布者记录的本机地址，仅进程内使用")
	output := flag.String("report", "", "不存在的去敏 JSON 路径")
	contract := flag.String("contract-profile", "", "本次候选 feature-profile.json，只绑定哈希，不加载运行时")
	count := flag.Int("samples", 30, "连接抽查数，至少 30")
	flag.Parse()
	if *pcap == "" || *labels == "" || *scenario == "" || *output == "" || *contract == "" || *count < 30 || *count > 1000 {
		return fmt.Errorf("须指定 pcap/labels/scenario/local-addr/report/contract-profile，samples 为 30..1000")
	}
	local, err := netip.ParseAddr(*anchor)
	if err != nil {
		return fmt.Errorf("local-addr 无效")
	}
	input, err := os.Open(*labels)
	if err != nil {
		return err
	}
	ls, err := probe.Labels(input, *scenario)
	input.Close()
	if err != nil {
		return err
	}
	r, err := probe.Audit(*pcap, ls, *scenario, local.Unmap(), *count)
	if err != nil {
		return err
	}
	r.Environment = map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "mode": "offline_reference_only"}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if r.BinaryHash, _, err = probe.FileHash(executable); err != nil {
		return err
	}
	if r.ContractProfileHash, _, err = probe.FileHash(*contract); err != nil {
		return err
	}
	if r.PCAPHash, r.PCAPBytes, err = probe.FileHash(*pcap); err != nil {
		return err
	}
	if r.LabelHash, r.LabelBytes, err = probe.FileHash(*labels); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Printf("scenario=%s labels=%d frames=%d samples=%d join=%s researchOnly=true\n", r.Scenario, r.LabelCount, r.Frames, len(r.Samples), r.JoinGate)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
