//go:build !cgo

package capture

import (
	"context"
	"errors"
	"testing"
)

// 纯 Go 包不能因用户传入有效接口名就意外进入实时采集或伪造内核丢包统计。
func TestPureGoBuildRejectsLiveCapture(t *testing.T) {
	handle, err := OpenLive("en0", []string{"en0"})
	if handle != nil || !errors.Is(err, ErrLiveCaptureUnavailable) {
		t.Fatalf("离线构建意外开放实时接口: %v", err)
	}
	h := &LiveHandle{}
	if _, _, err := h.Drops(); !errors.Is(err, ErrLiveCaptureUnavailable) {
		t.Fatal("未知内核丢包没有显式失败")
	}
	if err := h.Run(context.Background(), LiveOptions{}, nil); !errors.Is(err, ErrLiveCaptureUnavailable) {
		t.Fatal("离线构建的实时采集未失败关闭")
	}
}
