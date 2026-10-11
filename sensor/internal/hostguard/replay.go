package hostguard

import (
	"context"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
)

// ReplayClock 提供回放用的墙钟和等待；测试可注入虚拟时钟，生产使用 SystemClock。
type ReplayClock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// SystemClock 是真实墙钟；Sleep 可被 ctx 取消。
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }
func (SystemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ReplayOptions 控制冻结 PCAP 的 1 倍速回放。Start/End 为原事件时间分区，语义与 guardextract 相同。
type ReplayOptions struct {
	Clock      ReplayClock
	Start, End time.Time
	// CaptureStart 非零时表示传感器在该原事件时刻已开始采集：引擎时钟与上下文覆盖从此起算，
	// 1 倍速等待到首个报文；它不得晚于首个分区内报文，也不读取更早的报文。零值保持首包起算。
	CaptureStart time.Time
	TickInterval time.Duration
	Observe      func(LiveSample)
	// FixedOffset 仅用于已登记 lab 时钟；所有场景共用，不得由每个报文重新选择。
	FixedOffset *time.Duration
	// Check 在等待和处理前检查外部会话状态；不修改提取器状态或时间。
	Check func() error
}

// ReplayResult 把原事件时间与墙钟分开记录：原时间 = 观察中的事件时间 - Offset。
type ReplayResult struct {
	Offset      time.Duration
	SourceFirst time.Time
	SourceLast  time.Time
	WallStart   time.Time
	WallEnd     time.Time
	Packets     uint64
	MaxLag      time.Duration
}

// ReplayPCAP 以 1 倍速只读回放冻结 PCAP/PCAPNG，不打开网卡、不注入任何报文。
//
// 时间只平移一次：首个分区内报文确定整秒 Offset，此后所有报文时间 +Offset 送入同一因果引擎，
// 包间隔、窗口和特征值不变；emittedAt 取真实墙钟。等待期间按 TickInterval 推进引擎，使快照按时发出，
// 但 Tick 时刻不超过下一个待送报文的平移时间，文件读完后也不再 Tick，因此快照内容与 guardextract
// 对同一文件、同一身份/密钥的离线结果逐字段一致（emittedAt 除外，事件时间需减去 Offset）。
// ctx 取消时返回错误且不关闭引擎，调用方不得把部分输出报告为完成。
func ReplayPCAP(ctx context.Context, path string, e *Engine, o ReplayOptions) (ReplayResult, error) {
	var r ReplayResult
	clock := o.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	tick := o.TickInterval
	if tick == 0 {
		tick = 100 * time.Millisecond
	}
	if tick < time.Millisecond || tick > time.Second {
		return r, fmt.Errorf("回放 Tick 间隔无效")
	}
	if !e.clock.IsZero() || e.closed {
		return r, fmt.Errorf("回放需要新的引擎")
	}
	if o.FixedOffset != nil && (o.CaptureStart.IsZero() || *o.FixedOffset%time.Microsecond != 0) {
		return r, fmt.Errorf("固定偏移须绑定原始采集起点及微秒精度")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if o.Check != nil {
			return o.Check()
		}
		return nil
	}
	if err := check(); err != nil {
		return r, err
	}
	e.emissionClock = clock.Now
	started := false
	if !o.CaptureStart.IsZero() {
		r.WallStart = clock.Now().UTC()
		r.Offset = r.WallStart.Truncate(time.Second).Add(time.Second).Sub(o.CaptureStart.UTC().Truncate(time.Second))
		if o.FixedOffset != nil {
			r.Offset = *o.FixedOffset
		}
		at := o.CaptureStart.Add(r.Offset)
		for now := clock.Now(); now.Before(at); now = clock.Now() {
			if err := check(); err != nil {
				return r, err
			}
			if err := clock.Sleep(ctx, min(tick, at.Sub(now))); err != nil {
				return r, err
			}
		}
		if err := e.Tick(at); err != nil {
			return r, err
		}
		started = true
	}
	sawPacket := false
	var lastSample time.Time
	sample := func(at time.Time) {
		if o.Observe == nil {
			return
		}
		capacity, late := e.CaptureCounters()
		// 公开/冻结文件的历史丢包不可测，DropsKnown=false；不能当作连续健康证明。
		o.Observe(LiveSample{At: at, PacketsSeen: r.Packets, CapacityDrops: capacity, LateCount: late})
		lastSample = at
	}
	err := WalkPCAP(path, func(data []byte, ci gopacket.CaptureInfo, seq uint64) error {
		if !o.Start.IsZero() && ci.Timestamp.Before(o.Start) || !o.End.IsZero() && ci.Timestamp.After(o.End) {
			return nil
		}
		if err := check(); err != nil {
			return err
		}
		if !o.CaptureStart.IsZero() && ci.Timestamp.Before(o.CaptureStart) {
			return fmt.Errorf("采集起点晚于分区内首个报文")
		}
		if !started {
			r.WallStart = clock.Now().UTC()
			r.Offset = r.WallStart.Truncate(time.Second).Add(time.Second).Sub(ci.Timestamp.UTC().Truncate(time.Second))
		}
		if !sawPacket {
			r.SourceFirst = ci.Timestamp.UTC()
		}
		shifted := ci.Timestamp.Add(r.Offset)
		for {
			if err := check(); err != nil {
				return err
			}
			now := clock.Now()
			if !now.Before(shifted) {
				break
			}
			if err := clock.Sleep(ctx, min(shifted.Sub(now), tick)); err != nil {
				return err
			}
			if started {
				now = clock.Now()
				if now.After(shifted) {
					now = shifted
				}
				if err := e.Tick(now); err != nil {
					return err
				}
				sample(clock.Now())
			}
		}
		if lag := clock.Now().Sub(shifted); lag > r.MaxLag {
			r.MaxLag = lag
		}
		if err := e.Frame(data, ci.Length, shifted, seq); err != nil {
			return err
		}
		started, sawPacket = true, true
		r.Packets++
		if ci.Timestamp.After(r.SourceLast) {
			r.SourceLast = ci.Timestamp.UTC()
		}
		if now := clock.Now(); now.Sub(lastSample) >= tick {
			sample(now)
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	if !sawPacket {
		return r, fmt.Errorf("回放分区内没有报文")
	}
	if err = e.Close(); err != nil {
		return r, err
	}
	r.WallEnd = clock.Now().UTC()
	sample(r.WallEnd)
	return r, nil
}
