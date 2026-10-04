//go:build !cgo

package capture

import (
	"context"
	"errors"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/pipeline"
)

// FixedFilter 与 cgo 构建保持同一白名单；纯 Go 构建只支持离线 PCAP。
const FixedFilter = "ip or ip6"

var (
	ErrInterfaceNotAllowed = errors.New("抓包接口不在本机授权白名单内")
	// ErrLiveCaptureUnavailable 明确区分离线提取器与需要 libpcap/Npcap 的实时抓包程序。
	ErrLiveCaptureUnavailable = errors.New("纯 Go 构建仅支持离线提取；实时抓包需要 cgo 和 libpcap/Npcap")
)

// LiveHandle 保留编译接口；纯 Go 构建没有打开网卡的实现。
type LiveHandle struct {
	Interface string
}

// OpenLive 在任何接口参数下失败关闭，不能以离线构建启动实时采集。
func OpenLive(_ string, _ []string) (*LiveHandle, error) {
	return nil, ErrLiveCaptureUnavailable
}

// Close 不持有抓包句柄，不产生系统副作用。
func (*LiveHandle) Close() {}

// Drops 没有内核统计来源时返回明确错误，禁止把未知丢包写成零。
func (*LiveHandle) Drops() (int, int, error) { return 0, 0, ErrLiveCaptureUnavailable }

// LiveOptions 与 cgo 入口保持编译兼容；离线构建不调用该回调。
type LiveOptions struct {
	OnTick func(time.Time)
}

// Run 拒绝实时抓包，不能将未观测的空流水线作为成功运行。
func (*LiveHandle) Run(context.Context, LiveOptions, *pipeline.Pipeline) error {
	return ErrLiveCaptureUnavailable
}
