// Package flow 把报文聚合为双向流并按特征规格 §1.1 封流（unsw-nb15-flow-v4）。
//
// 确定性约定（Go 传感器与 Java 参考实现必须一致，G2 对拍依赖它）：
//   - 每个报文先检查自身流键：空闲超时或已满最长存活时间的旧流先导出，再处理报文；
//   - 其余流的超时扫描只在报文时间跨过整秒边界时执行（Sweep），扫描结果按 (末包时间, 首包时间, 流键) 排序；
//   - 导出序号 ExportSeq 按导出顺序递增，是窗口排序键的最终 tie-break（§3）。
//
// 只保存头部元数据与计数，不保存载荷。
package flow

import (
	"net/netip"
	"sort"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/spec"
)

// Endpoint 是（地址, 端口）；无端口协议端口为 0。
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

func less(a, b Endpoint) bool {
	if c := a.Addr.Compare(b.Addr); c != 0 {
		return c < 0
	}
	return a.Port < b.Port
}

// Key 是规范化流键：低端点在前（§1.1）。
type Key struct {
	Proto  uint8
	Lo, Hi Endpoint
}

func keyLess(a, b Key) bool {
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	if a.Lo != b.Lo {
		return less(a.Lo, b.Lo)
	}
	return less(a.Hi, b.Hi)
}

func keyOf(p *packet.Packet) Key {
	a, b := Endpoint{p.Src, p.SPort}, Endpoint{p.Dst, p.DPort}
	if less(b, a) {
		a, b = b, a
	}
	return Key{p.Proto, a, b}
}

// Flow 是一条正在聚合或已完成的流。计数口径见 §1.3（含 D11 折算）。
type Flow struct {
	Key          Key
	AF           uint8
	Init, Resp   Endpoint
	Start, Last  time.Time
	SPkts, DPkts int64
	// LabelAudit 只供显式开启的离线标签旁路，不参与特征计算或在线序列化。
	LabelAudit *LabelAudit
	SBytes     int64
	DBytes     int64
	// HandshakeSeen：TCP 首包为纯 SYN（§1.1 元数据）。
	HandshakeSeen bool
	Segment       int // 满最长存活时间切段后的段序号，0 为首段

	synTS, synAckTS, ackTS time.Time
	mssInit, mssResp       uint16
	finInit, finResp, rst  bool
}

// Completed 是已导出的流。
type Completed struct {
	*Flow
	Reason    string // tcp_fin、tcp_rst、idle_timeout、max_lifetime、shutdown
	ExportSeq int64
}

// micro 把时长截断到微秒后转为秒（§2.1：dur 保留微秒）。
func micro(d time.Duration) float64 { return float64(d.Microseconds()) / 1e6 }

// Dur 返回 末包时间 − 首包时间（秒，微秒精度）。
func (f *Flow) Dur() float64 { return micro(f.Last.Sub(f.Start)) }

// Handshake 返回 synack、ackdat（秒）；三者未按序齐全时全为 0（§2.1 说明）。
func (f *Flow) Handshake() (synack, ackdat float64) {
	if f.Key.Proto != 6 || f.synTS.IsZero() || f.synAckTS.IsZero() || f.ackTS.IsZero() {
		return 0, 0
	}
	return micro(f.synAckTS.Sub(f.synTS)), micro(f.ackTS.Sub(f.synAckTS))
}

// Diagnostics 是流表层面的计数（§6，不进契约）。
type Diagnostics struct {
	PostClosePackets int64 `json:"post_close_packets"`
	OrphanFragments  int64 `json:"orphan_fragments"`
	OversizePackets  int64 `json:"oversize_tcp_packets"`
	CapacityDrops    int64 `json:"flow_capacity_drops"`
	MaxActiveFlows   int   `json:"max_active_flows"`
}

type fragKey struct {
	af       uint8
	src, dst netip.Addr
	proto    uint8
	id       uint32
}

type fragRef struct {
	key Key
	at  time.Time
}

type contState struct {
	init    Endpoint
	segment int
	at      time.Time
}

// Table 是有界流表。不是线程安全的；由单个抓包循环串行调用。
type Table struct {
	mtu        int
	maxFlows   int
	labelAudit bool
	flows      map[Key]*Flow
	tombs      map[Key]time.Time
	cont       map[Key]contState
	frags      map[fragKey]fragRef
	lastSweep  time.Time
	seq        int64
	Diag       Diagnostics
}

// NewTable 创建流表。mtu 用于 D11 超大包判定；maxFlows 为活动流上限，超出时新流被丢弃并计数。
func NewTable(mtu, maxFlows int) *Table {
	return &Table{mtu: mtu, maxFlows: maxFlows, flows: map[Key]*Flow{}, tombs: map[Key]time.Time{},
		cont: map[Key]contState{}, frags: map[fragKey]fragRef{}}
}

// Active 返回活动流数。
// EnableLabelAudit 仅由离线提取入口启用；在线采集默认不创建标签统计。
func (t *Table) EnableLabelAudit() { t.labelAudit = true }

// LabelAudit 从传输层头长推算载荷长度，不读取内容。分片无法精确重建时标为不可靠。
type LabelAudit struct {
	SPayload int64 `json:"initiatorPayloadBytes"`
	DPayload int64 `json:"responderPayloadBytes"`
	SPackets int64 `json:"initiatorRawPackets"`
	DPackets int64 `json:"responderRawPackets"`
	Reliable bool  `json:"payloadLengthReliable"`
}

func (t *Table) Active() int { return len(t.flows) }

func (t *Table) complete(f *Flow, reason string, out []Completed) []Completed {
	t.seq++
	return append(out, Completed{Flow: f, Reason: reason, ExportSeq: t.seq})
}

// Accept 处理一个解析成功的报文，返回因此导出的流（含整秒扫描结果）。
func (t *Table) Accept(p *packet.Packet) []Completed {
	var out []Completed
	if t.lastSweep.IsZero() {
		t.lastSweep = p.TS
	} else if p.TS.Sub(t.lastSweep) >= time.Second {
		out = t.Sweep(p.TS)
	}
	if p.LaterFrag {
		t.acceptFragment(p)
		return out
	}
	k := keyOf(p)
	pureSYN := p.Proto == 6 && p.SYN && !p.ACK
	if ts, ok := t.tombs[k]; ok {
		if p.TS.Sub(ts) < spec.Tombstone && !pureSYN {
			t.Diag.PostClosePackets++
			return out
		}
		delete(t.tombs, k)
	}
	f := t.flows[k]
	if f != nil {
		switch {
		case p.TS.Sub(f.Last) >= spec.Idle(k.Proto):
			delete(t.flows, k)
			out = t.complete(f, "idle_timeout", out)
			f = nil
		case p.TS.Sub(f.Start) >= spec.MaxLifetime:
			delete(t.flows, k)
			t.cont[k] = contState{f.Init, f.Segment + 1, p.TS}
			out = t.complete(f, "max_lifetime", out)
			f = nil
		}
	}
	if f == nil {
		if len(t.flows) >= t.maxFlows {
			t.Diag.CapacityDrops++
			return out
		}
		f = &Flow{Key: k, AF: p.AF, Init: Endpoint{p.Src, p.SPort}, Resp: Endpoint{p.Dst, p.DPort},
			Start: p.TS, Last: p.TS, HandshakeSeen: pureSYN}
		if t.labelAudit {
			f.LabelAudit = &LabelAudit{Reliable: true}
		}
		if c, ok := t.cont[k]; ok && p.TS.Sub(c.at) < spec.Idle(k.Proto) {
			// §1.1：后续段继承首段的 initiator。
			// 续段首包若来自原 responder，则 responder 是本包发送方；否则保持本包目的端。
			f.Segment, f.Init = c.segment, c.init
			if c.init.Addr != p.Src || c.init.Port != p.SPort {
				f.Resp = Endpoint{p.Src, p.SPort}
			}
			f.HandshakeSeen = false
		}
		delete(t.cont, k)
		t.flows[k] = f
		if len(t.flows) > t.Diag.MaxActiveFlows {
			t.Diag.MaxActiveFlows = len(t.flows)
		}
	}
	if p.TS.After(f.Last) {
		f.Last = p.TS
	}
	fromInit := p.Src == f.Init.Addr && p.SPort == f.Init.Port
	if p.FirstFrag {
		t.frags[fragKey{p.AF, p.Src, p.Dst, p.Proto, p.FragID}] = fragRef{k, p.TS}
	}
	if p.Proto == 6 {
		t.tcpState(f, p, fromInit)
	}
	t.count(f, p, fromInit)
	if p.Proto == 6 && (f.rst || (f.finInit && f.finResp)) {
		delete(t.flows, k)
		t.tombs[k] = p.TS
		reason := "tcp_fin"
		if f.rst {
			reason = "tcp_rst"
		}
		out = t.complete(f, reason, out)
	}
	return out
}

func (t *Table) acceptFragment(p *packet.Packet) {
	ref, ok := t.frags[fragKey{p.AF, p.Src, p.Dst, p.Proto, p.FragID}]
	f := t.flows[ref.key]
	if !ok || f == nil || p.TS.Sub(ref.at) >= spec.FragmentWait {
		t.Diag.OrphanFragments++
		return
	}
	if p.TS.After(f.Last) {
		f.Last = p.TS
	}
	t.count(f, p, p.Src == f.Init.Addr)
}

func (t *Table) tcpState(f *Flow, p *packet.Packet, fromInit bool) {
	switch {
	case p.SYN && !p.ACK && fromInit:
		if f.synTS.IsZero() {
			f.synTS = p.TS
		}
		if p.MSS != 0 {
			f.mssInit = p.MSS
		}
	case p.SYN && p.ACK && !fromInit:
		if !f.synTS.IsZero() && f.synAckTS.IsZero() {
			f.synAckTS = p.TS
		}
		if p.MSS != 0 {
			f.mssResp = p.MSS
		}
	case !p.SYN && p.ACK && fromInit:
		if !f.synAckTS.IsZero() && f.ackTS.IsZero() {
			f.ackTS = p.TS
		}
	}
	if p.FIN {
		if fromInit {
			f.finInit = true
		} else {
			f.finResp = true
		}
	}
	if p.RST {
		f.rst = true
	}
}

// count 按 §1.3 累加包数与字节；IP 总长超过 MTU 的 TCP 包按对端通告的 MSS 折算为线路分段（D11）。
func (t *Table) count(f *Flow, p *packet.Packet, fromInit bool) {
	if a := f.LabelAudit; a != nil {
		if fromInit {
			a.SPackets++
		} else {
			a.DPackets++
		}
		if p.Proto != 6 || p.FirstFrag || p.LaterFrag || p.TCPHdr < 20 || p.IPTotal < p.IPHdr+p.TCPHdr || p.TotalFromCap {
			a.Reliable = false
		} else if fromInit {
			a.SPayload += int64(p.IPTotal - p.IPHdr - p.TCPHdr)
		} else {
			a.DPayload += int64(p.IPTotal - p.IPHdr - p.TCPHdr)
		}
	}
	segs, bytes := int64(1), int64(p.IPTotal)
	if p.Proto == 6 && !p.LaterFrag && p.TCPHdr >= 20 && p.IPTotal > t.mtu {
		mss := int(f.mssResp) // initiator 发出的分段受 responder 通告的 MSS 约束
		if !fromInit {
			mss = int(f.mssInit)
		}
		hdr := p.IPHdr + p.TCPHdr
		if mss == 0 {
			mss = t.mtu - hdr
		}
		if payload := p.IPTotal - hdr; mss > 0 && payload > 0 {
			n := (payload + mss - 1) / mss
			segs, bytes = int64(n), int64(payload+n*hdr)
			t.Diag.OversizePackets++
		}
	}
	if fromInit {
		f.SPkts += segs
		f.SBytes += bytes
	} else {
		f.DPkts += segs
		f.DBytes += bytes
	}
}

// Sweep 导出空闲超时与满最长存活时间的流，并清理过期的墓碑、续段与分片索引。
func (t *Table) Sweep(now time.Time) []Completed {
	t.lastSweep = now
	type due struct {
		f      *Flow
		reason string
	}
	var ds []due
	for k, f := range t.flows {
		switch {
		case now.Sub(f.Last) >= spec.Idle(k.Proto):
			ds = append(ds, due{f, "idle_timeout"})
		case now.Sub(f.Start) >= spec.MaxLifetime:
			ds = append(ds, due{f, "max_lifetime"})
			t.cont[k] = contState{f.Init, f.Segment + 1, now}
		default:
			continue
		}
		delete(t.flows, k)
	}
	sortDue := func(i, j int) bool {
		a, b := ds[i].f, ds[j].f
		if !a.Last.Equal(b.Last) {
			return a.Last.Before(b.Last)
		}
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		return keyLess(a.Key, b.Key)
	}
	sort.Slice(ds, sortDue)
	var out []Completed
	for _, d := range ds {
		out = t.complete(d.f, d.reason, out)
	}
	for k, ts := range t.tombs {
		if now.Sub(ts) >= spec.Tombstone {
			delete(t.tombs, k)
		}
	}
	for k, c := range t.cont {
		if now.Sub(c.at) >= spec.Idle(k.Proto) {
			delete(t.cont, k)
		}
	}
	for k, r := range t.frags {
		if now.Sub(r.at) >= spec.FragmentWait {
			delete(t.frags, k)
		}
	}
	return out
}

// Flush 在停止时导出全部活动流（先按超时规则扫描，其余记 shutdown），顺序确定。
func (t *Table) Flush(now time.Time) []Completed {
	out := t.Sweep(now)
	rest := make([]*Flow, 0, len(t.flows))
	for _, f := range t.flows {
		rest = append(rest, f)
	}
	sort.Slice(rest, func(i, j int) bool {
		a, b := rest[i], rest[j]
		if !a.Last.Equal(b.Last) {
			return a.Last.Before(b.Last)
		}
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		return keyLess(a.Key, b.Key)
	})
	for _, f := range rest {
		delete(t.flows, f.Key)
		out = t.complete(f, "shutdown", out)
	}
	return out
}
