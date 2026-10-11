// guardreplaydiff 逐字段比对 guardlive -pcap 的 1 倍速回放输出与 guardextract 对同一文件的离线输出。
//
// 回放观察的 firstSeenAt/lastPacketAt/asOf 减去运行摘要中的 timeOffsetMicros 后还原为原事件时间；
// emittedAt 是真实墙钟，两侧都不参与比较。离线侧按回放所用的 captureScope 做同一过滤。
// 摘要为 lab_pcap_replay 时另行忽略已登记的 lab 差异字段（见 internal/replaydiff）。
// 只读两份本地 JSONL，不访问网络；任一字段不一致返回非零。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/xyh/cyber-security/sensor/internal/replaydiff"
)

func run() (bool, error) {
	offline := flag.String("offline", "", "guardextract 输出 JSONL")
	replay := flag.String("replay", "", "guardlive -pcap 输出 JSONL")
	report := flag.String("report", "", "guardlive -pcap 的 -report 运行摘要")
	flag.Parse()
	if *offline == "" || *replay == "" || *report == "" {
		return false, fmt.Errorf("须指定 offline、replay、report")
	}
	rb, err := os.ReadFile(*report)
	if err != nil {
		return false, err
	}
	fo, err := os.Open(*offline)
	if err != nil {
		return false, err
	}
	defer fo.Close()
	fr, err := os.Open(*replay)
	if err != nil {
		return false, err
	}
	defer fr.Close()
	result, ok, err := replaydiff.Compare(fo, fr, rb)
	if err != nil {
		return false, err
	}
	en := json.NewEncoder(os.Stdout)
	en.SetIndent("", "  ")
	return ok, en.Encode(result)
}

func main() {
	ok, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardreplaydiff:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}
