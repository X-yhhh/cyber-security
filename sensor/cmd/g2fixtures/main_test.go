package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// 已提交到后端测试资源的 G2 fixtures 必须等于当前 Go 实现的输出（逐字节）。
// 失败说明流表/特征构造改了而 fixtures 未重新生成：运行 `go run ./cmd/g2fixtures -dir <下述目录>` 后提交。
var committed = filepath.Join("..", "..", "..", "backend", "src", "test", "resources", "feature-contract",
	"fixtures", "unsw-nb15-flow-v4-packet")

func TestCommittedFixturesAreReproducible(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, Files...), "checksums.json") {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(committed, name))
		if err != nil {
			t.Fatalf("读取已提交 fixture %s 失败: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s 与当前 Go 实现输出不一致；请重新生成 fixtures", name)
		}
	}
}
