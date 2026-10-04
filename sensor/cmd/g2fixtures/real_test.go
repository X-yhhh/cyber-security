package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 真实流量 fixtures 的 pcap 无法由代码重新生成（来自本机 en0 抓包并经 pcapanon 假名化），
// 这里只验证：用已提交的 pcap 与 fixture.json 中的参数重新提取，得到的期望输出与已提交文件逐字节相同。
var committedReal = filepath.Join("..", "..", "..", "backend", "src", "test", "resources", "feature-contract",
	"fixtures", "unsw-nb15-flow-v4-packet-real")

func TestCommittedRealFixturesAreReproducible(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(committedReal, "fixture.json"))
	if err != nil {
		t.Fatalf("读取已提交的真实流量 fixture.json 失败: %v", err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := GenerateFromPcap(dir, filepath.Join(committedReal, "capture.pcap"), fx.LocalAddrs, fx.Subnets); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, Files...), "checksums.json") {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(committedReal, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s 与当前 Go 实现输出不一致；请用 g2fixtures -pcap 重新生成", name)
		}
	}
}
