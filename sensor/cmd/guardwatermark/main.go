// guardwatermark 只离线复算既有私有头部轨迹（BE-10 第 1、2 条）：
// 在同一轨迹上比较读取水位的 tick 策略，并对上传视角中的 unknown 观察逐连接归因。
// 不开抓包句柄、不上传、不改写轨迹；输出只含聚合计数，不含端点。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// 只读取引擎需要的身份与地址，其余字段（上传、密钥路径等）一律忽略。
type sessionConfig struct {
	AssetID        string       `json:"assetId"`
	SensorID       string       `json:"sensorId"`
	BootID         string       `json:"bootId"`
	CaptureScopeID string       `json:"captureScopeId"`
	CaptureScope   string       `json:"captureScope"`
	Environment    string       `json:"environment"`
	KeyEpoch       int          `json:"keyEpoch"`
	LocalAddresses []netip.Addr `json:"localAddresses"`
}

// 策略只决定哪些已记录的 tick 送入引擎；帧、缺口与 close 原样保留。
var policies = []struct {
	Name, Description string
	keep              func(prevKind string, prevAt, at time.Time) bool
}{
	{"read_clock_every_read", "原实现：每次读出（帧或超时）后按读取墙钟推进水位", func(string, time.Time, time.Time) bool { return true }},
	{"read_clock_idle_only", "#88 实现：读出帧后只用包时间推进，仅空闲超时按墙钟推进", func(prevKind string, prevAt, at time.Time) bool {
		return !((prevKind == "frame" || prevKind == "gap") && prevAt.Equal(at))
	}},
}

type tupleKey struct {
	local, peer netip.AddrPort
	proto       uint8
}

// 每个连接在轨迹中的原始头部事实，用于解释提取器为何给出 unknown。
type tupleFacts struct {
	firstTS              time.Time
	firstSYN, firstACK   bool
	synTS, closeTS       []time.Time
	inboundSyn, outbound bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardwatermark:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "采集会话 config.json（私有）")
	tracePath := flag.String("trace", "", "完整关闭的头部轨迹 trace.jsonl（私有）")
	out := flag.String("out", "", "聚合结果 JSON；不含端点")
	flag.Parse()
	if *configPath == "" || *tracePath == "" || *out == "" {
		return fmt.Errorf("须指定 config、trace、out")
	}
	var c sessionConfig
	b, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.CaptureScope != "all_inbound_tcp" {
		return fmt.Errorf("只评估 all_inbound_tcp 会话")
	}
	digest, err := fileSHA256(*tracePath)
	if err != nil {
		return err
	}
	local := map[netip.Addr]bool{}
	for _, a := range c.LocalAddresses {
		local[a.Unmap()] = true
	}
	facts, traceSummary, err := collectFacts(*tracePath, local)
	if err != nil {
		return err
	}
	results := []any{}
	for _, p := range policies {
		r, err := evaluate(c, *tracePath, p.keep, facts, traceSummary.start)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
		r["policy"] = p.Name
		r["description"] = p.Description
		results = append(results, r)
	}
	summary := map[string]any{
		"tool":        "guardwatermark",
		"traceSha256": digest,
		"trace":       traceSummary.report(),
		"policies":    results,
		"boundary":    "离线复算同一私有轨迹；read_clock_idle_only 只模拟 tick 策略，读取时序仍是原 100ms 非 immediate 采集，immediate 模式的读取延迟变化须现场验证",
	}
	w, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

type traceStats struct {
	start, end                    time.Time
	frames, ticks, gaps, closes   int64
	idleTicks                     int64
	pureSynInbound, pureSynOutbnd int64
	tuples                        int
}

func (t traceStats) report() map[string]any {
	return map[string]any{"start": t.start, "end": t.end, "frames": t.frames, "ticks": t.ticks, "idleTicks": t.idleTicks,
		"gaps": t.gaps, "closes": t.closes, "pureSynInbound": t.pureSynInbound, "pureSynOutbound": t.pureSynOutbnd, "tcpTuples": t.tuples}
}

func readTrace(path string, visit func(hostguard.LiveEvent) error) error {
	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	closed := false
	for {
		var v hostguard.LiveEvent
		if err = d.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if closed {
			return fmt.Errorf("close 后仍有轨迹")
		}
		if err = visit(v); err != nil {
			return err
		}
		closed = v.Kind == "close"
	}
	if !closed {
		return fmt.Errorf("轨迹未完整关闭，滚动或仍在写入的轨迹不能复算")
	}
	return nil
}

func collectFacts(path string, local map[netip.Addr]bool) (map[tupleKey]*tupleFacts, traceStats, error) {
	facts := map[tupleKey]*tupleFacts{}
	var s traceStats
	prevKind, prevAt := "", time.Time{}
	err := readTrace(path, func(v hostguard.LiveEvent) error {
		if s.start.IsZero() {
			s.start = v.At
		}
		s.end = v.At
		switch v.Kind {
		case "frame":
			s.frames++
		case "tick":
			s.ticks++
			if !((prevKind == "frame" || prevKind == "gap") && prevAt.Equal(v.At)) {
				s.idleTicks++
			}
		case "gap":
			s.gaps++
		case "close":
			s.closes++
		}
		prevKind, prevAt = v.Kind, v.At
		if v.Kind != "frame" || v.ParseStatus != "ok" || v.Packet == nil || v.Packet.Proto != 6 {
			return nil
		}
		p := v.Packet
		src, dst := p.Src.Unmap(), p.Dst.Unmap()
		out := local[src]
		if out == local[dst] {
			return nil
		}
		k := tupleKey{netip.AddrPortFrom(dst, p.DPort), netip.AddrPortFrom(src, p.SPort), 6}
		if out {
			k = tupleKey{netip.AddrPortFrom(src, p.SPort), netip.AddrPortFrom(dst, p.DPort), 6}
		}
		f := facts[k]
		if f == nil {
			f = &tupleFacts{firstTS: p.TS, firstSYN: p.SYN, firstACK: p.ACK}
			facts[k] = f
		}
		if p.SYN && !p.ACK {
			f.synTS = append(f.synTS, p.TS)
			if out {
				s.pureSynOutbnd++
				f.outbound = true
			} else {
				s.pureSynInbound++
				f.inboundSyn = true
			}
		}
		if p.FIN || p.RST {
			f.closeTS = append(f.closeTS, p.TS)
		}
		return nil
	})
	s.tuples = len(facts)
	return facts, s, err
}

func evaluate(c sessionConfig, path string, keep func(string, time.Time, time.Time) bool, facts map[tupleKey]*tupleFacts, start time.Time) (map[string]any, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	var (
		total, uploaded, late, pass, fullCoverage30 int64
		direction                                   = map[string]int64{}
		delays                                      []float64
		reasonObs                                   = map[string]int64{}
		portObs                                     = map[string]int64{}
		reasonConn                                  = map[string]map[tupleKey]bool{}
		portConn                                    = map[string]map[tupleKey]bool{}
		unknownPass                                 int64
	)
	emit := func(v hostguard.Emission) error {
		total++
		o := v.Observation
		if o.Transport != "tcp" || o.Direction == "outbound" {
			return nil
		}
		uploaded++
		direction[o.Direction]++
		if o.Quality.LatePacket {
			late++
		}
		if !o.Quality.Defective() {
			pass++
			if o.Direction == "unknown" {
				unknownPass++
			}
		}
		for _, x := range o.Contexts {
			if x.WindowSeconds == 30 && x.CoverageMs >= 30000 {
				fullCoverage30++
			}
		}
		delays = append(delays, float64(o.EmittedAt.Sub(o.AsOf))/float64(time.Millisecond))
		if o.Direction != "unknown" {
			return nil
		}
		k := tupleKey{v.Endpoints.Local, v.Endpoints.Peer, v.Endpoints.Protocol}
		reason, port := attribute(k, facts[k], o.FirstSeenAt, start)
		reasonObs[reason]++
		portObs[port]++
		add(reasonConn, reason, k)
		add(portConn, port, k)
		return nil
	}
	e, err := hostguard.New(hostguard.Config{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID,
		CaptureScopeID: c.CaptureScopeID, Environment: c.Environment, KeyEpoch: c.KeyEpoch,
		PeerSecret: secret, LocalAddresses: c.LocalAddresses, Emit: emit})
	if err != nil {
		return nil, err
	}
	prevKind, prevAt := "", time.Time{}
	var skipped int64
	err = readTrace(path, func(v hostguard.LiveEvent) error {
		pk, pa := prevKind, prevAt
		prevKind, prevAt = v.Kind, v.At
		if v.Kind == "tick" && !keep(pk, pa, v.At) {
			skipped++
			return nil
		}
		return e.ApplyLiveEvent(v)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ticksSkipped":           skipped,
		"latePackets":            e.Stats["late_packets"],
		"frames":                 e.Stats["frames"],
		"observations":           total,
		"uploaded":               uploaded,
		"uploadedDirection":      direction,
		"uploadedLatePacket":     late,
		"uploadedLatePacketRate": ratio(late, uploaded),
		"uploadedQualityPass":    pass,
		"uploadedUnknownPass":    unknownPass,
		"uploadedFullCoverage30": fullCoverage30,
		"emissionDelayMs":        distribution(delays),
		"unknownByReason":        map[string]any{"observations": reasonObs, "connections": counts(reasonConn)},
		"unknownByPortPattern":   map[string]any{"observations": portObs, "connections": counts(portConn)},
	}, nil
}

// attribute 只解释 unknown 的来源，不据此改写方向；端口形态仅作旁证。
func attribute(k tupleKey, f *tupleFacts, firstSeen, start time.Time) (string, string) {
	port := "ambiguous"
	switch lp, pp := k.local.Port(), k.peer.Port(); {
	case lp >= 49152 && pp < 49152:
		port = "local_ephemeral_peer_service"
	case lp < 49152 && pp >= 49152:
		port = "local_service_peer_ephemeral"
	}
	if f == nil {
		return "no_trace_fact", port
	}
	before := func(ts []time.Time) bool {
		for _, t := range ts {
			if !t.After(firstSeen) {
				return true
			}
		}
		return false
	}
	switch {
	case before(f.closeTS):
		return "after_fin_rst_tombstone", port
	case before(f.synTS):
		return "pure_syn_seen_not_accepted", port
	case f.firstSYN && f.firstACK:
		return "first_seen_syn_ack", port
	case f.firstTS.Sub(start) < 120*time.Second:
		return "midstream_within_first_120s", port
	default:
		return "midstream_later", port
	}
}

func add(m map[string]map[tupleKey]bool, k string, t tupleKey) {
	if m[k] == nil {
		m[k] = map[tupleKey]bool{}
	}
	m[k][t] = true
}

func counts(m map[string]map[tupleKey]bool) map[string]int {
	r := map[string]int{}
	for k, v := range m {
		r[k] = len(v)
	}
	return r
}

func ratio(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return math.Round(float64(a)/float64(b)*1e6) / 1e6
}

// 分位数与 P1R-8 口径一致：排序后取向上取整的位置。
func distribution(v []float64) map[string]any {
	if len(v) == 0 {
		return map[string]any{"count": 0}
	}
	sort.Float64s(v)
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(v)))) - 1
		if i < 0 {
			i = 0
		}
		return math.Round(v[i]*1000) / 1000
	}
	return map[string]any{"count": len(v), "p50Ms": q(.5), "p95Ms": q(.95), "p99Ms": q(.99), "maxMs": q(1)}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
