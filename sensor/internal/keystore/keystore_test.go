package keystore

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestMemoryStore(t *testing.T) {
	s := NewMemory()
	if _, err := s.Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatal("空库应返回 ErrNotFound")
	}
	if err := s.Put("svc", "acct", "mch_1.x"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get("svc", "acct"); err != nil || v != "mch_1.x" {
		t.Fatalf("读取错误: %q %v", v, err)
	}
	if err := s.Delete("svc", "acct"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatal("重复删除应返回 ErrNotFound")
	}
}

// 真实钥匙串往返只在显式开启时运行（会在登录钥匙串中短暂写入一条测试条目并删除）。
func TestKeychainRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SENSOR_KEYCHAIN_IT") != "1" {
		t.Skip("设置 SENSOR_KEYCHAIN_IT=1 在 macOS 上运行")
	}
	s := Default()
	const svc, acct = "cyber-security-sensor-test", "keystore-test"
	_ = s.Delete(svc, acct)
	credential := "mch_9.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123"
	if err := s.Put(svc, acct, credential); err != nil {
		t.Fatal(err)
	}
	defer s.Delete(svc, acct)
	if v, err := s.Get(svc, acct); err != nil || v != credential {
		t.Fatalf("钥匙串往返失败: %v", err)
	}
}

func TestKeychainRejectsInjection(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS 专用")
	}
	s := Default()
	if err := s.Put("svc", "acct", "x\nadd-generic-password -s evil"); err == nil {
		t.Fatal("含换行的凭据应被拒绝")
	}
	if _, err := s.Get("svc; rm", "acct"); err == nil {
		t.Fatal("含非法字符的服务名应被拒绝")
	}
}
