package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// runLiveSource 将已授权、已打开的现场句柄接入 1.0.0 健康链；调用方在返回后关闭句柄。
// check 检查上传器的致命错误，即使空闲且尚未形成完整健康窗口也及时停止。
// 捕获异常仍封口带缺口的尾窗；观察器自身失败后不重试签发，保留原错误供调用方报告。
// source/now 可替换为合成输入，单测无需网卡、真实报文或抓包权限。
func runLiveSource(ctx context.Context, source hostguard.LiveSource, engine *hostguard.Engine, now func() time.Time,
	trace func(hostguard.LiveEvent) error, observer *capturehealth.Observer, check func() error) (runErr error) {
	if observer != nil && observer.Version() != capturehealth.Version {
		return fmt.Errorf("现场采集必须使用健康协议 1.0.0")
	}
	var last hostguard.LiveSample
	var observeErr error
	defer func() {
		if observer != nil && observeErr == nil && !last.At.IsZero() {
			runErr = errors.Join(runErr, observer.Finish(last))
		}
	}()
	return hostguard.RunLiveObserved(ctx, source, engine, now, trace, func(sample hostguard.LiveSample) error {
		last = sample
		if check != nil {
			observeErr = check()
		}
		if observer != nil && observeErr == nil {
			observeErr = observer.Observe(sample)
		}
		return observeErr
	})
}
