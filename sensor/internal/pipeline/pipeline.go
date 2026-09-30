// Package pipeline 串起 解析 → 流表 → 特征构造 → 输出，与抓包源无关（实时网卡或 pcap 文件）。
//
// 时间全部取报文时间：流表整秒扫描与重排序释放都以最近一个报文的时间为“当前时间”，
// 这样同一个 pcap 文件无论何时回放结果都相同（G2 对拍依赖它）。实时抓包在读超时时调用 Tick，
// 用墙钟推进空闲流的导出。
package pipeline

import (
	"time"

	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/packet"
)

// Diagnostics 汇总解析、流表与构造三层计数（特征规格 §6，不进契约）。
type Diagnostics struct {
	Frames      int64               `json:"frames"`
	ParseStatus map[string]int64    `json:"parse_status"`
	CloseReason map[string]int64    `json:"close_reasons"`
	Flow        flow.Diagnostics    `json:"flow"`
	Feature     feature.Diagnostics `json:"feature"`
}

// Counters 是一个健康窗口内的计数，由 Snapshot 取走后清零。
//
// 两项都在重排序释放时计数，而不是在流导出时：记录要在缓冲中停留约 61 s，若 Seen 按导出计、
// Ready 按释放计，同一窗口内 Ready 可能大于 Seen，违反后端健康窗口校验
// （flowsEmitted ≤ flowsSeen，flowsDropped ≤ flowsSeen − flowsEmitted）。上报层用
// Ready 减去本窗口内因缓冲溢出丢弃的记录作为 flowsEmitted，丢弃数作为 flowsDropped。
type Counters struct {
	FlowsSeen int64 // 本窗口释放的记录（任意状态）
	Ready     int64 // 其中构造为 ready 的记录
}

// Pipeline 不是线程安全的；由单个抓包循环串行调用。
type Pipeline struct {
	tab     *flow.Table
	builder *feature.Builder
	emit    func([]feature.Record)
	now     time.Time
	diag    Diagnostics
	window  Counters
}

// New 创建流水线。emit 收到每批释放的全部记录（含非 ready，调用方自行过滤）。
func New(tab *flow.Table, builder *feature.Builder, emit func([]feature.Record)) *Pipeline {
	return &Pipeline{tab: tab, builder: builder, emit: emit,
		diag: Diagnostics{ParseStatus: map[string]int64{}, CloseReason: map[string]int64{}}}
}

// Frame 处理一帧以太网数据。
func (p *Pipeline) Frame(data []byte, wireLen int, ts time.Time) {
	p.diag.Frames++
	pk, st := packet.ParseEthernet(data, wireLen, ts)
	p.diag.ParseStatus[st.String()]++
	if st != packet.OK {
		return
	}
	if ts.After(p.now) {
		p.now = ts
	}
	p.push(p.tab.Accept(&pk))
	p.release(false)
}

// Tick 在没有报文时推进时间（实时抓包读超时）。now 早于最近报文时间时忽略。
func (p *Pipeline) Tick(now time.Time) {
	if now.Before(p.now) {
		return
	}
	p.now = now
	p.push(p.tab.Sweep(now))
	p.release(false)
}

// Close 导出全部活动流并释放重排序缓冲。
func (p *Pipeline) Close() {
	p.push(p.tab.Flush(p.now))
	p.release(true)
	p.diag.Flow = p.tab.Diag
}

func (p *Pipeline) push(cs []flow.Completed) {
	for _, c := range cs {
		p.diag.CloseReason[c.Reason]++
	}
	p.builder.Push(cs)
}

func (p *Pipeline) release(all bool) {
	rs := p.builder.Release(p.now, all)
	if len(rs) == 0 {
		return
	}
	p.window.FlowsSeen += int64(len(rs))
	for _, r := range rs {
		if r.Status == feature.StatusReady {
			p.window.Ready++
		}
	}
	p.emit(rs)
}

// Snapshot 返回并清零当前健康窗口计数，同时返回活动流数与重排序缓冲深度。
func (p *Pipeline) Snapshot() (Counters, int, int) {
	c := p.window
	p.window = Counters{}
	return c, p.tab.Active(), p.builder.Pending()
}

// Diagnostics 返回累计诊断计数的快照。
func (p *Pipeline) Diagnostics() Diagnostics {
	d := p.diag
	d.Flow = p.tab.Diag
	d.Feature = p.builder.Diag
	return d
}

// Policy 返回地址策略，供实时抓包刷新本机地址。
func (p *Pipeline) Policy() *feature.AddressPolicy { return p.builder.Policy() }
