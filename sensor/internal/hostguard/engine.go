package hostguard

import (
	"container/heap"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"
)

type event struct {
	p       Packet
	issue   Quality
	invalid bool
}
type eventHeap []event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	a, b := h[i].p, h[j].p
	return a.TS.Before(b.TS) || a.TS.Equal(b.TS) && a.CaptureSeq < b.CaptureSeq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(event)) }
func (h *eventHeap) Pop() any     { a := *h; x := a[len(a)-1]; *h = a[:len(a)-1]; return x }

type timer struct {
	at  time.Time
	key tuple
	id  string
}
type timerHeap []timer

func (h timerHeap) Len() int { return len(h) }
func (h timerHeap) Less(i, j int) bool {
	return h[i].at.Before(h[j].at) || h[i].at.Equal(h[j].at) && h[i].id < h[j].id
}
func (h timerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *timerHeap) Push(x any)   { *h = append(*h, x.(timer)) }
func (h *timerHeap) Pop() any     { a := *h; x := a[len(a)-1]; *h = a[:len(a)-1]; return x }

type tuple struct {
	local, peer netip.AddrPort
	proto       uint8
}
type connection struct {
	id, direction     string
	service           *uint16
	synSeq, synAckSeq uint32
	initiatorOutbound bool
	state             int
	closed            bool
	tombstone         time.Time
}
type moments struct {
	n        int64
	mean, m2 float64
}

func (m *moments) add(v float64) {
	m.n++
	d := v - m.mean
	m.mean += d / float64(m.n)
	// 显式 float64 舍入禁止编译器融合乘加，确保 arm64/amd64 的 JSON 内容哈希一致。
	m.m2 += float64(d * (v - m.mean))
}
func (m moments) std() float64 {
	if m.n == 0 {
		return 0
	}
	return math.Sqrt(max(0, m.m2/float64(m.n)))
}

type flow struct {
	id                    string
	conn                  *connection
	key                   tuple
	peer, transport, af   string
	first, last, next     time.Time
	index                 int
	packetsAtSnapshot     int64
	features              Features
	lengths, iats         moments
	syn, synAck, rst, fin int64
	finOut, finIn         bool
	quality               Quality
	ref                   *string
	expires               *time.Time
}

// Engine 串行消费一个捕获域；调用方不得并发调用。Emit 错误永久停止，不能提交部分成功报告。
type Engine struct {
	cfg                                         Config
	local                                       map[netip.Addr]bool
	flows                                       map[tuple]*flow
	connections                                 map[tuple]*connection
	buffer                                      eventHeap
	timers                                      timerHeap
	windows                                     []*contextWindow
	clock, watermark, coverageStart, issueUntil time.Time
	issue                                       Quality
	lastSeq, idSeq                              uint64
	closed                                      bool
	dropMarker                                  bool
	err                                         error
	emissionClock                               func() time.Time
	Stats                                       map[string]int64
}

func New(c Config) (*Engine, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	e := &Engine{cfg: c, local: map[netip.Addr]bool{}, flows: map[tuple]*flow{}, connections: map[tuple]*connection{}, Stats: map[string]int64{}}
	for _, a := range c.LocalAddresses {
		e.local[a.Unmap()] = true
	}
	e.resetWindows()
	return e, nil
}
func (e *Engine) resetWindows() {
	e.windows = []*contextWindow{newWindow(1), newWindow(5), newWindow(30)}
}
func (e *Engine) nextID(kind string) string { e.idSeq++; return e.cfg.id(kind, e.idSeq) }

// Frame 为 PCAP 和 live 共用的输入，captureSeq 由读取方递增，不允许离线全局排序。
func (e *Engine) Frame(data []byte, wire int, at time.Time, seq uint64) error {
	p, status := Parse(data, wire, at, seq, e.cfg.MTU)
	return e.frameParsed(p, status)
}

func (e *Engine) frameParsed(p Packet, status string) error {
	e.Stats["parse_"+status]++
	if status == "non_ip" {
		return e.enqueue(event{p: p, invalid: true})
	}
	if status != "ok" {
		// 已知与本机无关的坏帧不污染本捕获域；连地址头都不可读时才保守传播。
		if p.Src.IsValid() && p.Dst.IsValid() && !e.local[p.Src.Unmap()] && !e.local[p.Dst.Unmap()] {
			return e.enqueue(event{p: p, invalid: true})
		}
		return e.enqueue(event{p: p, invalid: true, issue: p.Quality})
	}
	return e.Push(p)
}

// Push 接受已严格解析的头部元数据，仅供输入适配器和 golden 使用。
func (e *Engine) Push(p Packet) error {
	if !p.Src.IsValid() || !p.Dst.IsValid() || p.IPTotal <= 0 || p.TS.IsZero() {
		return fmt.Errorf("无效报文元数据")
	}
	p.TS = p.TS.UTC().Truncate(time.Microsecond)
	p.Src = p.Src.Unmap()
	p.Dst = p.Dst.Unmap()
	return e.enqueue(event{p: p})
}
func (e *Engine) enqueue(v event) error {
	if e.closed {
		return fmt.Errorf("提取器已关闭")
	}
	if e.err != nil {
		return e.err
	}
	if v.p.CaptureSeq <= e.lastSeq {
		return fmt.Errorf("captureSeq 必须严格递增")
	}
	e.lastSeq = v.p.CaptureSeq
	if v.p.TS.IsZero() {
		return fmt.Errorf("缺少捕获时间")
	}
	e.Stats["frames"]++
	if e.clock.IsZero() {
		e.clock = v.p.TS
		e.coverageStart = v.p.TS
	}
	if !e.watermark.IsZero() && !v.p.TS.After(e.watermark) {
		e.Stats["late_packets"]++
		e.defect(Quality{LatePacket: true}, e.watermark)
		return e.err
	}
	if len(e.buffer) >= e.cfg.MaxBufferedPackets {
		e.Stats["buffer_drops"]++
		// 保留一个有界缺陷事件，在其事件时间生效，不能提前污染尚未发布的较早快照。
		if !e.dropMarker {
			heap.Push(&e.buffer, event{p: v.p, invalid: true, issue: Quality{CapacityDrop: true}})
			e.dropMarker = true
		}
		return e.Tick(v.p.TS)
	}
	heap.Push(&e.buffer, v)
	return e.Tick(v.p.TS)
}

// Tick 推进事件时钟，即使没有新报文也能产生准时 prefix/idle；墙钟倒退不使水位后退。
func (e *Engine) Tick(now time.Time) error {
	if e.closed {
		return fmt.Errorf("提取器已关闭")
	}
	if e.err != nil {
		return e.err
	}
	now = now.UTC().Truncate(time.Microsecond)
	if e.clock.IsZero() {
		e.clock = now
		e.coverageStart = now
	}
	if now.After(e.clock) {
		e.clock = now
	}
	e.release(e.clock.Add(-ReorderDelay))
	return e.err
}
func (e *Engine) release(until time.Time) {
	if !e.watermark.IsZero() && !until.After(e.watermark) {
		return
	}
	for len(e.buffer) > 0 && !e.buffer[0].p.TS.After(until) && e.err == nil {
		v := heap.Pop(&e.buffer).(event)
		if v.invalid && v.issue.CapacityDrop {
			e.dropMarker = false
		}
		e.runTimers(v.p.TS, false)
		if v.issue.Defective() {
			e.defect(v.issue, v.p.TS)
		}
		if !v.invalid {
			e.accept(v.p)
		}
	}
	e.runTimers(until, true)
	e.watermark = until
}

// Gap 先完成已收到的缓冲，再重新预热；未知丢包不能报告成零。调用时间使用事件时钟。
func (e *Engine) Gap(at time.Time) error {
	if err := e.Tick(at); err != nil {
		return err
	}
	e.release(e.clock)
	e.defect(Quality{CaptureGap: true}, e.clock)
	e.Stats["capture_gaps"]++
	return e.err
}
func (e *Engine) defect(q Quality, at time.Time) {
	e.coverageStart = at
	e.resetWindows()
	if at.After(e.issueUntil) {
		e.issue = Quality{}
	}
	e.issue.merge(q)
	e.issueUntil = at.Add(30 * time.Second)
	for _, f := range e.flows {
		f.quality.merge(q)
		f.ref = nil
		f.expires = nil
	}
}
func (e *Engine) key(p Packet) (tuple, bool, bool) {
	a, b := e.local[p.Src], e.local[p.Dst]
	if a == b {
		return tuple{}, false, false
	}
	if a {
		return tuple{netip.AddrPortFrom(p.Src, p.SPort), netip.AddrPortFrom(p.Dst, p.DPort), p.Proto}, true, true
	}
	return tuple{netip.AddrPortFrom(p.Dst, p.DPort), netip.AddrPortFrom(p.Src, p.SPort), p.Proto}, false, true
}
func (e *Engine) accept(p Packet) {
	k, out, ok := e.key(p)
	if !ok {
		e.Stats["outside_anchor"]++
		return
	}
	c := e.connections[k]
	f := e.flows[k]
	freshSyn := p.Proto == 6 && p.SYN && !p.ACK
	newEpoch := freshSyn && (c == nil || c.closed || c.state == 0 || c.state >= 3 || c.synSeq != p.Seq || c.initiatorOutbound != out)
	if newEpoch && f != nil {
		e.finish(f, p.TS, "new_syn")
		f = nil
	}
	if c != nil && c.closed && !freshSyn && !p.TS.After(c.tombstone) {
		e.Stats["tombstone_packets"]++
		return
	}
	if f == nil && len(e.flows) >= e.cfg.MaxFlows {
		e.Stats["flow_drops"]++
		e.defect(Quality{CapacityDrop: true}, p.TS)
		return
	}
	newParent := c == nil || newEpoch || (p.Proto != 6 && f == nil)
	if newParent {
		if c == nil && len(e.connections) >= e.cfg.MaxConnections {
			e.Stats["connection_drops"]++
			e.defect(Quality{CapacityDrop: true}, p.TS)
			return
		}
		c = &connection{id: e.nextID("parent"), direction: "unknown"}
		if freshSyn || p.Proto == 17 {
			c.direction = "inbound"
			port := k.local.Port()
			if out {
				c.direction = "outbound"
				port = k.peer.Port()
			}
			if port > 0 {
				c.service = &port
			} else {
				c.direction = "unknown"
			}
			c.initiatorOutbound = out
		}
		if freshSyn {
			c.synSeq = p.Seq
			c.state = 1
		}
		e.connections[k] = c
	}
	if c.closed {
		c.direction = "unknown"
		c.service = nil
		c.state = 0
	}
	if f == nil {
		proto := map[uint8]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}[p.Proto]
		if proto == "" {
			proto = "other"
		}
		af := "ipv4"
		if p.Src.Is6() {
			af = "ipv6"
		}
		f = &flow{id: e.nextID("flow"), conn: c, key: k, peer: e.cfg.peer(k.peer.Addr()), transport: proto, af: af, first: p.TS, last: p.TS, next: p.TS.Add(time.Second), quality: Quality{ClockSkewMs: e.cfg.ClockSkewMs}}
		if !p.TS.After(e.issueUntil) {
			f.quality.merge(e.issue)
		}
		e.flows[k] = f
		e.schedule(f)
	}
	if p.TS.Before(f.last) {
		panic("内部释放顺序错误")
	}
	n := f.features.PacketsOutbound + f.features.PacketsInbound
	if n > 0 {
		f.iats.add(float64(p.TS.Sub(f.last)) / float64(time.Microsecond))
	}
	f.last = p.TS
	f.quality.merge(p.Quality)
	if out {
		f.features.PacketsOutbound++
		f.features.BytesOutbound += int64(p.IPTotal)
	} else {
		f.features.PacketsInbound++
		f.features.BytesInbound += int64(p.IPTotal)
	}
	if n == 0 || p.IPTotal < f.features.LengthMin {
		f.features.LengthMin = p.IPTotal
	}
	f.features.LengthMax = max(f.features.LengthMax, p.IPTotal)
	f.lengths.add(float64(p.IPTotal))
	if freshSyn {
		f.syn++
	}
	if p.SYN && p.ACK {
		f.synAck++
		if c.state == 1 && out != c.initiatorOutbound && p.Ack == c.synSeq+1 {
			c.state = 2
			c.synAckSeq = p.Seq
		}
	}
	if !p.SYN && p.ACK && c.state == 2 && out == c.initiatorOutbound && p.Ack == c.synAckSeq+1 && p.Seq == c.synSeq+1 {
		c.state = 3
	}
	if p.FIN {
		f.fin++
		if out {
			f.finOut = true
		} else {
			f.finIn = true
		}
	}
	if p.RST {
		f.rst++
	}
	ce := contextEvent{at: p.TS, peer: f.peer}
	if c.service != nil {
		ce.port = *c.service
	}
	if newParent {
		ce.start = 1
	}
	if freshSyn {
		ce.syn = 1
	}
	if p.RST {
		ce.rst = 1
	}
	if out {
		ce.out = int64(p.IPTotal)
	} else {
		ce.in = int64(p.IPTotal)
	}
	for _, w := range e.windows {
		w.advance(p.TS)
	}
	if len(e.windows[2].queue)-e.windows[2].head >= e.cfg.MaxContextEvents {
		e.Stats["context_drops"]++
		e.defect(Quality{CapacityDrop: true}, p.TS)
	}
	for _, w := range e.windows {
		w.add(ce)
	}
	e.Stats["accepted_packets"]++
	// 每次续证都来自新包；定时发快照不能更新引用截止时间。
	if e.cfg.Environment != "research" && e.cfg.Lease != nil && c.direction != "unknown" && p.Proto == 6 && !f.quality.Defective() && skewTrusted(e.clockSkew()) {
		o := e.observation(f, p.TS, nil)
		ref, expiry, err := e.cfg.Lease(o, Endpoints{k.local, k.peer, k.proto})
		if err != nil || ref == "" || expiry.After(p.TS.Add(15*time.Second)) || !expiry.After(p.TS) {
			f.ref = nil
			f.expires = nil
			e.Stats["lease_rejections"]++
		} else {
			f.ref = &ref
			f.expires = &expiry
		}
	}
	if p.RST {
		e.finish(f, p.TS, "rst")
	} else if f.finOut && f.finIn {
		e.finish(f, p.TS, "fin")
	}
}

func (e *Engine) deadline(f *flow) time.Time {
	idle := 30 * time.Second
	if f.key.proto != 6 {
		idle = 10 * time.Second
	}
	d := f.last.Add(idle)
	if v := f.first.Add(120 * time.Second); v.Before(d) {
		d = v
	}
	if f.next.Before(d) {
		d = f.next
	}
	return d
}
func (e *Engine) schedule(f *flow) { heap.Push(&e.timers, timer{e.deadline(f), f.key, f.id}) }
func (e *Engine) runTimers(until time.Time, inclusive bool) {
	for len(e.timers) > 0 && e.err == nil {
		t := e.timers[0]
		if t.at.After(until) || !inclusive && t.at.Equal(until) {
			break
		}
		heap.Pop(&e.timers)
		f := e.flows[t.key]
		if f == nil || f.id != t.id {
			continue
		}
		d := e.deadline(f)
		if d.After(t.at) {
			e.schedule(f)
			continue
		}
		idle := 30 * time.Second
		if f.key.proto != 6 {
			idle = 10 * time.Second
		}
		switch {
		case !d.Before(f.first.Add(120 * time.Second)):
			e.finish(f, d, "max_lifetime")
		case !d.Before(f.last.Add(idle)):
			e.finish(f, d, "idle")
		default:
			if f.features.PacketsOutbound+f.features.PacketsInbound > f.packetsAtSnapshot {
				e.emit(f, d, nil)
			}
			if f.next.Equal(f.first.Add(time.Second)) {
				f.next = f.first.Add(5 * time.Second)
			} else {
				f.next = f.next.Add(5 * time.Second)
			}
			e.schedule(f)
		}
	}
}
func (e *Engine) observation(f *flow, at time.Time, reason *string) Observation {
	v := f.features
	v.ElapsedMs = float64(at.Sub(f.first)) / float64(time.Millisecond)
	v.LengthMean = f.lengths.mean
	v.LengthStd = f.lengths.std()
	if f.iats.n > 0 {
		a, b := f.iats.mean, f.iats.std()
		v.IATMeanUs = &a
		v.IATStdUs = &b
	}
	if f.key.proto == 6 {
		a, b, c, d, h := f.syn, f.synAck, f.rst, f.fin, f.conn.state == 3
		v.SynCount = &a
		v.SynAckCount = &b
		v.RstCount = &c
		v.FinCount = &d
		v.HandshakeSeen = &h
	}
	profile := "flow-prefix-v1"
	if reason != nil {
		profile = "flow-final-v1"
	}
	contexts := make([]Context, 3)
	for i, w := range e.windows {
		contexts[i] = w.snapshot(f.peer, at, e.coverageStart)
	}
	ref, expiry := f.ref, f.expires
	if expiry != nil && !at.Before(*expiry) {
		ref = nil
		expiry = nil
	}
	emitted := maxTime(e.clock, at)
	if e.emissionClock != nil {
		emitted = maxTime(e.emissionClock().UTC().Truncate(time.Microsecond), at)
	}
	quality := f.quality
	quality.ClockSkewMs = e.clockSkew()
	return Observation{ContractVersion: Version, AssetID: e.cfg.AssetID, SensorID: e.cfg.SensorID, BootID: e.cfg.BootID, CaptureScopeID: e.cfg.CaptureScopeID, FlowID: f.id, ParentConnectionID: f.conn.id, SnapshotIndex: f.index, Profile: profile, Environment: e.cfg.Environment, FirstSeenAt: f.first, LastPacketAt: f.last, AsOf: at, EmittedAt: emitted, AddressFamily: f.af, Transport: f.transport, Direction: f.conn.direction, ServiceClass: serviceClass(f.transport, f.conn.service), ServicePort: f.conn.service, PeerKey: f.peer, KeyEpoch: e.cfg.KeyEpoch, TargetRef: ref, TargetExpiresAt: expiry, Features: v, Contexts: contexts, Quality: quality, CloseReason: reason}
}

// clockSkew 在快照导出时取偏差：实时来源优先，过期即 null；离线提取沿用配置值（默认 null）。
func (e *Engine) clockSkew() *float64 {
	if e.cfg.ClockSkew == nil {
		return e.cfg.ClockSkewMs
	}
	v, ok := e.cfg.ClockSkew()
	if !ok {
		return nil
	}
	f := float64(v)
	return &f
}

func skewTrusted(v *float64) bool { return v != nil && math.Abs(*v) <= 1000 }

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (e *Engine) emit(f *flow, at time.Time, reason *string) {
	o := e.observation(f, at, reason)
	o.ObservationID = e.cfg.id(f.id, uint64(f.index))
	f.index++
	f.packetsAtSnapshot = f.features.PacketsOutbound + f.features.PacketsInbound
	e.err = e.cfg.Emit(Emission{o, Endpoints{f.key.local, f.key.peer, f.key.proto}})
	e.Stats["observations"]++
}
func (e *Engine) finish(f *flow, at time.Time, reason string) {
	e.emit(f, at, &reason)
	delete(e.flows, f.key)
	if reason == "fin" || reason == "rst" {
		f.conn.closed = true
		f.conn.tombstone = at.Add(5 * time.Second)
	}
}

// Close 仅表输入结束，不伪造 FIN/idle；相同文件和 boot/secret 得到可重试的固定观察 ID。
func (e *Engine) Close() error {
	if e.closed {
		return e.err
	}
	if e.err != nil {
		e.closed = true
		return e.err
	}
	e.release(e.clock)
	fs := make([]*flow, 0, len(e.flows))
	for _, f := range e.flows {
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].id < fs[j].id })
	for _, f := range fs {
		if e.err != nil {
			break
		}
		e.finish(f, e.clock, "eof")
	}
	e.closed = true
	return e.err
}
