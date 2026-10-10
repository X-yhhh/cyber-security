// Package capturehealth 在 Go 侧生成 host-guard-capture-health/1.0.0 连续健康窗口。
//
// 观察器独立于特征引擎：只读捕获句柄的累计计数（读包数、内核丢包、容量丢弃），不读取模型特征或分数。
// 每个窗口不超过 MaxWindow、首尾相接，previousSha256 引用前一窗口完整 payload 的 RFC 8785 JCS 摘要。
// 未知计数输出 null，不填 0；轮询停顿超过窗口上限时按上限切分并标记 captureGap 与未知计数，
// 不能用连续序号掩盖缺口。采集器从不声明 healthy 或预算恢复，合格与否由服务端推导。
package capturehealth

import (
	"fmt"
	"regexp"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

const Version = "host-guard-capture-health/1.0.0"

// MaxWindow 是契约规定的单窗口上限。
const MaxWindow = 5 * time.Second

// Counters 是累计计数；nil 表示不可测。
type Counters struct {
	PacketsSeen   *int64 `json:"packetsSeen"`
	KernelDrops   *int64 `json:"kernelDrops"`
	CapacityDrops *int64 `json:"capacityDrops"`
}

// Metrics 只包含接口允许的可选字段。
type Metrics struct {
	LateCount   int64 `json:"lateCount"`
	QueueMax    int64 `json:"queueMax"`
	MemoryBytes int64 `json:"memoryBytes"`
}

// Window 与 POST /machine/sensors/{id}/health-windows 请求体逐字段对应。
type Window struct {
	HealthVersion     string   `json:"healthVersion"`
	HealthWindowID    string   `json:"healthWindowId"`
	AssetID           string   `json:"assetId"`
	SensorID          string   `json:"sensorId"`
	ObserverSessionID string   `json:"observerSessionId"`
	CaptureScopeID    string   `json:"captureScopeId"`
	Sequence          int64    `json:"sequence"`
	IntervalStart     string   `json:"intervalStart"`
	IntervalEnd       string   `json:"intervalEnd"`
	PreviousSha256    *string  `json:"previousSha256"`
	CounterStart      Counters `json:"counterStart"`
	CounterEnd        Counters `json:"counterEnd"`
	CaptureGap        bool     `json:"captureGap"`
	ClockSkewMs       *int64   `json:"clockSkewMs"`
	ConfigSha256      string   `json:"configSha256"`
	BuildSha256       string   `json:"buildSha256"`
	Metrics           *Metrics `json:"metrics,omitempty"`
}

// Identity 来自已批准的传感器配置；任一字段变化必须新建观察器会话。
type Identity struct {
	AssetID, SensorID, CaptureScopeID, ConfigSha256, BuildSha256 string
}

// Options 中 Skew 返回最近一次可信的时钟偏差（毫秒），不可信时 ok=false；QueueMax/Memory 可为 nil。
type Options struct {
	Window   time.Duration
	Skew     func() (int64, bool)
	QueueMax func() int64
	Memory   func() int64
	NewID    func() string
	Emit     func(Window) error
}

// Observer 非并发安全，须在捕获 goroutine 中按样本时间顺序调用。
type Observer struct {
	id       Identity
	o        Options
	session  string
	seq      int64
	prev     *string
	started  bool
	start    time.Time
	startC   Counters
	gap      bool
	last     hostguard.LiveSample
	finished bool
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// New 为一次物理捕获会话创建观察器，observerSessionId 每次进程/捕获句柄重建都换新。
func New(id Identity, o Options) (*Observer, error) {
	for _, v := range []string{id.AssetID, id.SensorID, id.CaptureScopeID} {
		if !uuidPattern.MatchString(v) {
			return nil, fmt.Errorf("健康身份必须为小写 UUID")
		}
	}
	if !shaPattern.MatchString(id.ConfigSha256) || !shaPattern.MatchString(id.BuildSha256) {
		return nil, fmt.Errorf("健康配置/程序摘要无效")
	}
	if o.Window == 0 {
		o.Window = time.Second
	}
	if o.Window < 100*time.Millisecond || o.Window > MaxWindow || o.Emit == nil || o.NewID == nil {
		return nil, fmt.Errorf("健康窗口参数无效")
	}
	session := o.NewID()
	if !uuidPattern.MatchString(session) {
		return nil, fmt.Errorf("观察器会话必须为 UUID")
	}
	return &Observer{id: id, o: o, session: session}, nil
}

func (b *Observer) Session() string { return b.session }

func counters(s hostguard.LiveSample) Counters {
	packets, capacity := int64(s.PacketsSeen), s.CapacityDrops
	c := Counters{PacketsSeen: &packets, CapacityDrops: &capacity}
	if s.DropsKnown {
		drops := int64(s.Drops)
		c.KernelDrops = &drops
	}
	return c
}

// Observe 消费一次轮询样本；跨过窗口长度时输出窗口。样本时间倒退视为缺口并重新起算当前窗口。
func (b *Observer) Observe(s hostguard.LiveSample) error {
	if b.finished {
		return fmt.Errorf("健康观察器已结束")
	}
	s.At = s.At.UTC()
	if !b.started {
		b.started, b.start, b.startC, b.gap, b.last = true, s.At, counters(s), s.Gap, s
		return nil
	}
	if !s.At.After(b.last.At) {
		b.gap = true
		if s.At.Before(b.last.At) {
			return nil
		}
	}
	b.gap = b.gap || s.Gap
	// 两次样本间隔超过上限：中间计数无法归属，按上限切出未知计数窗口并标记缺口。
	for s.At.Sub(b.start) > MaxWindow {
		end := b.start.Add(MaxWindow)
		if err := b.close(end, Counters{}, true); err != nil {
			return err
		}
		// 停顿的剩余部分同样无法证明连续捕获。
		b.gap = true
	}
	b.last = s
	if s.At.Sub(b.start) >= b.o.Window {
		return b.close(s.At, counters(s), b.gap)
	}
	return nil
}

// Finish 输出最后一个不完整窗口；之后不再接受样本。
func (b *Observer) Finish(s hostguard.LiveSample) error {
	if b.finished {
		return nil
	}
	if b.started {
		if s.At.UTC().After(b.last.At) {
			if err := b.Observe(s); err != nil {
				return err
			}
		}
		if b.last.At.After(b.start) {
			if err := b.close(b.last.At, counters(b.last), b.gap); err != nil {
				return err
			}
		}
	}
	b.finished = true
	return nil
}

func (b *Observer) close(end time.Time, endC Counters, gap bool) error {
	b.seq++
	w := Window{HealthVersion: Version, HealthWindowID: b.o.NewID(), AssetID: b.id.AssetID, SensorID: b.id.SensorID,
		ObserverSessionID: b.session, CaptureScopeID: b.id.CaptureScopeID, Sequence: b.seq,
		IntervalStart: b.start.Format(time.RFC3339Nano), IntervalEnd: end.Format(time.RFC3339Nano),
		PreviousSha256: b.prev, CounterStart: b.startC, CounterEnd: endC, CaptureGap: gap,
		ConfigSha256: b.id.ConfigSha256, BuildSha256: b.id.BuildSha256}
	if b.o.Skew != nil {
		if v, ok := b.o.Skew(); ok {
			w.ClockSkewMs = &v
		}
	}
	m := Metrics{LateCount: b.last.LateCount}
	if b.o.QueueMax != nil {
		m.QueueMax = b.o.QueueMax()
	}
	if b.o.Memory != nil {
		m.MemoryBytes = b.o.Memory()
	}
	w.Metrics = &m
	digest, err := jcs.SHA256(w)
	if err != nil {
		return err
	}
	if err = b.o.Emit(w); err != nil {
		return err
	}
	b.prev = &digest
	b.start, b.startC, b.gap = end, endC, false
	return nil
}
