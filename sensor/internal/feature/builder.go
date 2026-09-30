package feature

import (
	"net/netip"
	"sort"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/spec"
)

// 记录结论。只有 StatusReady 的记录上报；其余只计入 diagnostics。
const (
	StatusReady          = "ready"
	StatusWindowNotReady = "window_not_ready"
	StatusLate           = "late_event"
	StatusRejected       = "rejected"
)

// Features 按契约字段顺序（§2.1、§2.2）；encoding/json 按结构体字段顺序输出。
type Features struct {
	Dur           float64 `json:"dur"`
	SBytes        int64   `json:"sbytes"`
	DBytes        int64   `json:"dbytes"`
	SLoad         float64 `json:"sload"`
	DLoad         float64 `json:"dload"`
	TCPRTT        float64 `json:"tcprtt"`
	AckDat        float64 `json:"ackdat"`
	SynAck        float64 `json:"synack"`
	SMean         int64   `json:"smean"`
	DMean         int64   `json:"dmean"`
	SPkts         int64   `json:"spkts"`
	DPkts         int64   `json:"dpkts"`
	CtSrvSrc      int     `json:"ct_srv_src"`
	CtSrvDst      int     `json:"ct_srv_dst"`
	CtDstLtm      int     `json:"ct_dst_ltm"`
	CtSrcLtm      int     `json:"ct_src_ltm"`
	CtSrcDportLtm int     `json:"ct_src_dport_ltm"`
	Proto         string  `json:"proto"`
	Service       string  `json:"service"`
}

// Record 是一条完成流的构造结论。地址只在内存中用于窗口计数，不进入 Record。
type Record struct {
	RecordKey     string
	FlowStartAt   time.Time
	FlowEndAt     time.Time
	ExportSeq     int64
	AF            string
	Viewpoint     string
	HandshakeSeen bool
	CloseReason   string
	Status        string
	Reason        string // 非 ready 时的原因码
	Features      *Features
}

// Diagnostics 是构造层计数（§6，不进契约）。
type Diagnostics struct {
	Excluded map[string]int64 `json:"flows_excluded"`
	ByStatus map[string]int64 `json:"records_by_status"`
}

type member struct {
	end, start time.Time
	seq        int64
	init, resp netip.Addr
	respPort   uint16
	service    string
}

func memberLess(a, b *member) bool {
	if !a.end.Equal(b.end) {
		return a.end.Before(b.end)
	}
	if !a.start.Equal(b.start) {
		return a.start.Before(b.start)
	}
	return a.seq < b.seq
}

// window 是单个地址族的最近 N 条已完成流（§3），排序键 (flowEndAt, flowStartAt, exportSeq)，
// allowedLatenessSeconds = 0：不大于已接纳最大键的记录按迟到拒绝，不回填。
type window struct {
	members []*member
	last    *member
}

func (w *window) add(m *member) bool {
	if w.last != nil && !memberLess(w.last, m) {
		return false
	}
	w.members = append(w.members, m)
	if len(w.members) > spec.WindowSize {
		w.members = w.members[1:]
	}
	w.last = m
	return true
}

func (w *window) count(pred func(*member) bool) int {
	n := 0
	for _, m := range w.members {
		if pred(m) {
			n++
		}
	}
	return n
}

type pending struct {
	c   flow.Completed
	cls Class
}

// Builder 串起 排除/视角 → 重排序 → 分地址族窗口 → 特征。不是线程安全的。
type Builder struct {
	policy  *AddressPolicy
	keyBase string
	pending []pending
	windows map[string]*window
	Diag    Diagnostics
}

// NewBuilder 创建构造器。keyBase 是本进程的记录键前缀（如随机启动标识），记录键为 keyBase:exportSeq。
func NewBuilder(policy *AddressPolicy, keyBase string) *Builder {
	return &Builder{policy: policy, keyBase: keyBase, windows: map[string]*window{},
		Diag: Diagnostics{Excluded: map[string]int64{}, ByStatus: map[string]int64{}}}
}

// Policy 返回地址策略，供抓包循环刷新本机地址。
func (b *Builder) Policy() *AddressPolicy { return b.policy }

// Push 接收刚导出的流：排除的只计数，其余进入重排序缓冲。
func (b *Builder) Push(cs []flow.Completed) {
	for _, c := range cs {
		cls := b.policy.Classify(c.Init.Addr, c.Resp.Addr)
		if cls.Excluded != "" {
			b.Diag.Excluded[cls.Excluded]++
			continue
		}
		b.pending = append(b.pending, pending{c, cls})
	}
}

// Release 释放 flowEndAt ≤ now − ReorderDelay 的记录（all=true 时全部释放），按窗口排序键入窗并构造。
// 在同一进程内，Go 流表的导出时机保证释放后的记录不会再遇到更早的流（见 flow 包注释），因此不产生迟到。
func (b *Builder) Release(now time.Time, all bool) []Record {
	sort.SliceStable(b.pending, func(i, j int) bool {
		x, y := b.pending[i].c, b.pending[j].c
		return memberLess(&member{end: x.Last, start: x.Start, seq: x.ExportSeq},
			&member{end: y.Last, start: y.Start, seq: y.ExportSeq})
	})
	cut := now.Add(-spec.ReorderDelay)
	n := 0
	for n < len(b.pending) && (all || !b.pending[n].c.Last.After(cut)) {
		n++
	}
	ready := b.pending[:n]
	out := make([]Record, 0, n)
	for _, p := range ready {
		r := b.build(p)
		b.Diag.ByStatus[r.Status]++
		out = append(out, r)
	}
	b.pending = append([]pending(nil), b.pending[n:]...)
	return out
}

// Pending 返回重排序缓冲中的记录数。
func (b *Builder) Pending() int { return len(b.pending) }

func (b *Builder) build(p pending) Record {
	c := p.c
	r := Record{RecordKey: recordKey(b.keyBase, c.ExportSeq), FlowStartAt: c.Start, FlowEndAt: c.Last,
		ExportSeq: c.ExportSeq, AF: p.cls.AF, Viewpoint: p.cls.Viewpoint, HandshakeSeen: c.HandshakeSeen,
		CloseReason: c.Reason}
	service := spec.Service(c.Key.Proto, c.Resp.Port)
	w := b.windows[p.cls.AF]
	if w == nil {
		w = &window{}
		b.windows[p.cls.AF] = w
	}
	m := &member{end: c.Last, start: c.Start, seq: c.ExportSeq, init: c.Init.Addr, resp: c.Resp.Addr,
		respPort: c.Resp.Port, service: service}
	if !w.add(m) {
		r.Status, r.Reason = StatusLate, StatusLate
		return r
	}
	// 逐流值校验：与 Java FeatureBuilder.invalidFlowValue 同口径。流表产生的值只可能在
	// 续段中 initiator 没有发包时违反 spkts ≥ 1。
	if c.SPkts < 1 || c.DPkts < 0 || c.SBytes < 0 || c.DBytes < 0 {
		r.Status, r.Reason = StatusRejected, "value_invalid"
		return r
	}
	if len(w.members) < spec.WindowSize {
		r.Status, r.Reason = StatusWindowNotReady, StatusWindowNotReady
		return r
	}
	f := perFlow(c)
	f.Proto, f.Service = spec.Proto(c.Key.Proto), service
	f.CtSrvSrc = w.count(func(o *member) bool { return o.service == m.service && o.init == m.init })
	f.CtSrvDst = w.count(func(o *member) bool { return o.service == m.service && o.resp == m.resp })
	f.CtDstLtm = w.count(func(o *member) bool { return o.resp == m.resp })
	f.CtSrcLtm = w.count(func(o *member) bool { return o.init == m.init })
	f.CtSrcDportLtm = w.count(func(o *member) bool { return o.init == m.init && o.respPort == m.respPort })
	r.Status, r.Features = StatusReady, &f
	return r
}

// perFlow 计算 §2.1 #0～#11 与 §4 边界。浮点运算次序与 Java 参考实现相同，保证逐位一致。
func perFlow(c flow.Completed) Features {
	dur := c.Dur()
	synack, ackdat := c.Handshake()
	f := Features{Dur: dur, SBytes: c.SBytes, DBytes: c.DBytes, SPkts: c.SPkts, DPkts: c.DPkts,
		SynAck: synack, AckDat: ackdat, TCPRTT: synack + ackdat}
	if dur > 0 && c.SPkts > 1 {
		f.SLoad = float64(c.SBytes) * 8 * float64(c.SPkts-1) / float64(c.SPkts) / dur
	}
	if dur > 0 && c.DPkts > 1 {
		f.DLoad = float64(c.DBytes) * 8 * float64(c.DPkts-1) / float64(c.DPkts) / dur
	}
	f.SMean = roundDiv(c.SBytes, c.SPkts)
	f.DMean = roundDiv(c.DBytes, c.DPkts)
	return f
}

// roundDiv 返回 round(a / b)（四舍五入，b = 0 时为 0）。用整数运算避免浮点在 .5 处的双端差异。
func roundDiv(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return (2*a + b) / (2 * b)
}

func recordKey(base string, seq int64) string {
	return base + ":" + itoa(seq)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
