//go:build !windows

package privdrop

import (
	"os"
	"testing"
)

func TestFromSudoRequiresNonRootCaller(t *testing.T) {
	for _, env := range [][2]string{{"", ""}, {"0", "0"}, {"abc", "20"}, {"501", ""}} {
		t.Setenv("SUDO_UID", env[0])
		t.Setenv("SUDO_GID", env[1])
		if _, err := FromSudo(); err == nil {
			t.Fatalf("SUDO_UID=%q SUDO_GID=%q 应拒绝", env[0], env[1])
		}
	}
	t.Setenv("SUDO_UID", itoa(os.Getuid()))
	t.Setenv("SUDO_GID", itoa(os.Getgid()))
	if os.Getuid() == 0 {
		t.Skip("以 root 运行测试时无法验证普通用户解析")
	}
	got, err := FromSudo()
	if err != nil || got.UID != os.Getuid() || got.Home == "" {
		t.Fatalf("应解析当前用户: %+v %v", got, err)
	}
}

func TestDropRejectsInvalidTarget(t *testing.T) {
	for _, tg := range []Target{{}, {UID: 0, GID: 20, Home: "/x"}, {UID: 501, GID: 0, Home: "/x"}, {UID: 501, GID: 20}} {
		if Drop(tg) == nil {
			t.Fatalf("无效目标应拒绝: %+v", tg)
		}
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	s := ""
	for v > 0 {
		s = string(rune('0'+v%10)) + s
		v /= 10
	}
	return s
}
