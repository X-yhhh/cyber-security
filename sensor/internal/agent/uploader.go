package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/spec"
	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

// Submitter 抽象批次提交，便于测试替换。
type Submitter interface {
	SubmitBatch(ctx context.Context, idempotencyKey string, b uplink.Batch) (uplink.Receipt, error)
}

// Uploader 把 ready 记录攒成批次并异步上报。
//
// 线程模型：Add、Flush、TakeDropped 只由抓包线程调用（与流水线同一 goroutine）；Run 在独立 goroutine 中
// 消费有界队列。队列满时丢弃新批次并计数（不挤掉旧批次），保证丢弃数只计入当前健康窗口。
type Uploader struct {
	sub          Submitter
	state        *State
	local        LocalConfig
	cfgVersion   string
	queue        chan []uplink.RecordOut
	buf          []uplink.RecordOut
	dropped      int64
	queueMax     int64
	backoffStart time.Duration
	backoffMax   time.Duration
	// logf 记录重试原因（只含序号、状态码与错误码，不含记录内容或凭据）。
	logf func(format string, args ...any)
}

// NewUploader 创建上报器；队列容量为 local.SpoolBatches 个批次。
func NewUploader(sub Submitter, state *State, local LocalConfig, cfgVersion string) *Uploader {
	return &Uploader{sub: sub, state: state, local: local, cfgVersion: cfgVersion,
		queue: make(chan []uplink.RecordOut, local.SpoolBatches), backoffStart: time.Second, backoffMax: time.Minute,
		logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "sensor: "+format+"\n", args...) }}
}

// Add 接收流水线释放的记录，只保留 ready 记录；攒满一批即入队。
func (u *Uploader) Add(rs []feature.Record) {
	now := time.Now().UTC()
	for _, r := range rs {
		if r.Status != feature.StatusReady || r.Features == nil {
			continue
		}
		raw, err := json.Marshal(r.Features)
		if err != nil {
			u.dropped++
			continue
		}
		u.buf = append(u.buf, uplink.RecordOut{RecordKey: r.RecordKey, FlowStartAt: r.FlowStartAt.UTC(),
			FlowEndAt: r.FlowEndAt.UTC(), ObservedAt: now, DirectionBasis: spec.DirectionBasis, Features: raw,
			Viewpoint: r.Viewpoint, AddressFamily: r.AF, HandshakeSeen: r.HandshakeSeen})
		if len(u.buf) == uplink.MaxRecordsPerBatch {
			u.Flush()
		}
	}
}

// Flush 把未满的缓冲作为一个批次入队（缓冲为空时不做事）。
func (u *Uploader) Flush() {
	if len(u.buf) == 0 {
		return
	}
	b := u.buf
	u.buf = nil
	select {
	case u.queue <- b:
		if d := int64(len(u.queue)); d > u.queueMax {
			u.queueMax = d
		}
	default:
		u.dropped += int64(len(b))
	}
}

// TakeDropped 返回并清零本窗口的丢弃记录数与队列最大深度。调用前应先 Flush。
func (u *Uploader) TakeDropped() (dropped, queueMax int64) {
	dropped, queueMax = u.dropped, u.queueMax
	u.dropped, u.queueMax = 0, int64(len(u.queue))
	return
}

// Close 关闭队列；Run 发送完剩余批次后返回。
func (u *Uploader) Close() {
	u.Flush()
	close(u.queue)
}

// ErrUploadStopped 包装导致上报停止的 Stale/Fatal 错误。
var ErrUploadStopped = errors.New("批次上报已停止")

// Run 消费队列直到队列关闭或 ctx 取消。可重试错误按指数退避重发同一批次（同一序号与幂等键）；
// Stale（配置失效/映射未批准）与 Fatal 立即返回，调用方停止抓包，不自动放宽任何条件。
func (u *Uploader) Run(ctx context.Context) error {
	for records := range u.queue {
		seq, err := u.state.Allocate(u.cfgVersion)
		if err != nil {
			return fmt.Errorf("%w: 序号无法持久化: %v", ErrUploadStopped, err)
		}
		key := fmt.Sprintf("sensor-%d:%s:%d", u.local.SensorID, u.cfgVersion, seq)
		batch := uplink.Batch{DataSourceID: u.local.DataSourceID, ConfigVersion: u.cfgVersion, Sequence: seq,
			ObservedAt: time.Now().UTC(), SourceMappingVersion: u.local.SourceMappingVersion,
			FeatureContractVersion: spec.ContractVersion, Records: records}
		if err := u.send(ctx, key, batch); err != nil {
			return err
		}
	}
	return nil
}

func (u *Uploader) send(ctx context.Context, key string, b uplink.Batch) error {
	wait := u.backoffStart
	for {
		_, err := u.sub.SubmitBatch(ctx, key, b)
		if err == nil {
			return nil
		}
		var ue *uplink.Error
		if !errors.As(err, &ue) || ue.Class != uplink.Retryable {
			return fmt.Errorf("%w: %v", ErrUploadStopped, err)
		}
		u.logf("批次 %d 提交失败（%v），%s 后重试", b.Sequence, err, wait)
		select {
		case <-ctx.Done():
			// 停止时仍有批次未送达：不能当作正常退出，否则调用方会以退出码 0 掩盖数据未上报。
			return fmt.Errorf("%w: 停止时批次 %d 仍未送达（最后错误: %v），队列中另有 %d 批",
				ErrUploadStopped, b.Sequence, err, len(u.queue))
		case <-time.After(wait):
		}
		if wait *= 2; wait > u.backoffMax {
			wait = u.backoffMax
		}
	}
}
