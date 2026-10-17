//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureLocksAreExclusivePerInterface(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(d, 0700)
	release, err := captureLock(d, "utun9")
	if err != nil {
		t.Fatal(err)
	}
	if unlock, err := captureLock(d, "utun9"); err == nil {
		unlock()
		t.Fatal("重复采集未拒绝")
	}
	other, err := captureLock(d, "en0")
	if err != nil {
		t.Fatal(err)
	}
	other()
	release()
	again, err := captureLock(d, "utun9")
	if err != nil {
		t.Fatal(err)
	}
	again()
	os.Chmod(d, 0755)
	if _, err := captureLock(d, "utun9"); err == nil {
		t.Fatal("宽权限目录未拒绝")
	}
	os.Chmod(d, 0700)
	os.Symlink(filepath.Join(d, "utun9.capture.lock"), filepath.Join(d, "utun8.capture.lock"))
	if _, err := captureLock(d, "utun8"); err == nil {
		t.Fatal("符号链接未拒绝")
	}
}
