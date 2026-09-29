//go:build !windows

// Package privdrop 在 sudo 启动时把进程从 root 降到调用 sudo 的普通用户（路线 B D13）。
//
// 用法：以 root 打开抓包句柄（BPF 描述符不受之后的 uid 变化影响）后立即 Drop；之后读取凭据、联网、
// 写状态文件都以普通用户身份进行。不修改 /dev/bpf* 权限，不创建用户组，不注册常驻服务。
package privdrop

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Target 是降权目标。
type Target struct {
	UID, GID int
	Name     string
	Home     string
}

// FromSudo 从 sudo 设置的 SUDO_UID/SUDO_GID 解析降权目标。不是经 sudo 从普通用户启动时返回错误：
// 以 root 直接运行（如 launchd）无法确定降权目标，fail-closed。
func FromSudo() (Target, error) {
	uid, errU := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, errG := strconv.Atoi(os.Getenv("SUDO_GID"))
	if errU != nil || errG != nil || uid <= 0 || gid <= 0 {
		return Target{}, errors.New("以 root 运行时必须经 sudo 从普通用户启动，抓包句柄打开后降到该用户")
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return Target{}, fmt.Errorf("找不到 sudo 调用者: %w", err)
	}
	return Target{UID: uid, GID: gid, Name: u.Username, Home: u.HomeDir}, nil
}

// Drop 依次设置附加组、gid、uid，并核对降权结果：真实/有效 uid 与 gid 均为目标值，且无法恢复 root。
// 任一步失败都返回错误，调用方必须退出，不得带着 root 继续运行。
func Drop(t Target) error {
	if t.UID <= 0 || t.GID <= 0 || t.Home == "" {
		return errors.New("降权目标无效")
	}
	if err := syscall.Setgroups([]int{t.GID}); err != nil {
		return fmt.Errorf("设置附加组失败: %w", err)
	}
	if err := syscall.Setgid(t.GID); err != nil {
		return fmt.Errorf("设置 gid 失败: %w", err)
	}
	if err := syscall.Setuid(t.UID); err != nil {
		return fmt.Errorf("设置 uid 失败: %w", err)
	}
	if os.Getuid() != t.UID || os.Geteuid() != t.UID || os.Getgid() != t.GID || os.Getegid() != t.GID {
		return errors.New("降权后身份核对失败")
	}
	if syscall.Setuid(0) == nil {
		return errors.New("降权后仍能恢复 root，拒绝继续")
	}
	// 钥匙串与状态目录按普通用户的 HOME 解析。
	for k, v := range map[string]string{"HOME": t.Home, "USER": t.Name, "LOGNAME": t.Name} {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}
