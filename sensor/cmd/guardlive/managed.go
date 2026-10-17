package main

import (
	"context"
	"fmt"
	"time"
)

// validateManaged 保留短窗口入口；零时长只能由真实直接父进程托管，不向 lab/research 扩权。
func validateManaged(c config, duration time.Duration, parentPID, actualParent int, live bool) error {
	if parentPID == 0 {
		if duration == 0 {
			return fmt.Errorf("持续采集必须由后端托管")
		}
		return nil
	}
	if parentPID <= 1 || actualParent != parentPID || !live || duration != 0 ||
		c.Environment != "authorized" || c.CaptureScope != scopeAllInbound || c.Upload == nil ||
		!time.Now().Before(c.AuthorizedUntil) {
		return fmt.Errorf("后端托管采集范围或父进程无效")
	}
	return nil
}

// watchParent 同时覆盖正常退出和 SIGKILL 后的孤儿进程；PPID 改变后不等待上传网络恢复。
func watchParent(ctx context.Context, cancel context.CancelFunc, parentPID int, parent func() int) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if parent() != parentPID {
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
