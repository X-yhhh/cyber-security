//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// captureLock 在打开 BPF 前持有接口锁；稳定私有目录跨运行复用，关闭自动释放，不删除锁文件。
// 旧单服务配置可不指定；演示配置必须指定。不同接口互不阻塞，同接口重复启动拒绝。
func captureLock(directory, iface string) (func(), error) {
	if directory == "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(directory) || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(iface) {
		return nil, fmt.Errorf("采集锁路径无效")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != filepath.Clean(directory) {
		return nil, fmt.Errorf("采集锁目录不能包含软链接")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		return nil, fmt.Errorf("采集锁目录必须为当前用户的 0700 目录")
	}
	f, err := os.OpenFile(filepath.Join(directory, iface+".capture.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(st.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		f.Close()
		return nil, fmt.Errorf("采集锁文件不可信")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("接口已有采集进程")
	}
	return func() { f.Close() }, nil
}
