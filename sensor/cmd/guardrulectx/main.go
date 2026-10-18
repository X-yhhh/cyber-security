// guardrulectx 只离线复算既有私有头部轨迹（BE-10 第 3 条）：
// 对上传视角的观察按冻结阈值复算四条窗口规则，并把每次命中所依赖的同对端上下文
// 按连接发起方拆分（本机发起 / 对端发起 / 采集前已建立），给出连接、对端与 30 秒桶分母。
// 不开抓包、不上传、不改规则；输出只含聚合计数与服务端口号，不含地址。
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

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

// 冻结策略中的四条窗口规则（与能力说明 6.4 表一致）；本工具只复算，不改阈值。
type rule struct {
	ID, Family string
	Window     int
	Field      string
	Threshold  float64
}

var rules = []rule{
	{"scan-ports", "port_scan", 5, "peerDistinctServicePorts", 39},
	{"brute-starts", "brute_force", 30, "peerFlowStarts", 5},
	{"flood-bytes", "dos_flood", 1, "peerBytesInbound", 41260},
	{"slow-starts", "dos_slow", 30, "peerFlowStarts", 21},
}

// 连接发起方：只依据轨迹中是否见到起始纯 SYN 及其方向，不使用端口推断。
const (
	classLocal       = "local_initiated"
	classPeer        = "peer_initiated"
	classPreexisting = "preexisting_no_syn"
)

type tupleKey struct {
	local, peer netip.AddrPort
}

type tupleState struct {
	class  string
	synSeq uint32
}

type peerEvent struct {
	at      time.Time
	class   string
	start   bool
	inBytes int64
	port    uint16
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardrulectx:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "采集会话 config.json（私有）")
	tracePath := flag.String("trace", "", "完整关闭的头部轨迹 trace.jsonl（私有）")
	out := flag.String("out", "", "聚合结果 JSON；不含地址")
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
	local := map[netip.Addr]bool{}
	for _, a := range c.LocalAddresses {
		local[a.Unmap()] = true
	}
	events, tuples, err := collect(*tracePath, local)
	if err != nil {
		return err
	}
	report, err := evaluate(c, *tracePath, events, tuples)
	if err != nil {
		return err
	}
	report["tool"] = "guardrulectx"
	report["tickPolicy"] = "read_clock_idle_only（与 51b37fe 现行采集一致）"
	report["boundary"] = "冻结规则离线复算；发起方只依据轨迹内起始纯 SYN，采集前已建立的连接无法确定发起方；结构判定不是逐条人工真值"
	w, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
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

// classify 维护每个连接的发起方，返回本包对应的发起方与是否为新连接起点。
func classify(states map[tupleKey]*tupleState, k tupleKey, out, freshSyn bool, seq uint32) (string, bool) {
	s := states[k]
	if freshSyn && (s == nil || s.synSeq != seq || s.class == classPreexisting) {
		class := classPeer
		if out {
			class = classLocal
		}
		states[k] = &tupleState{class: class, synSeq: seq}
		return class, true
	}
	if s == nil {
		states[k] = &tupleState{class: classPreexisting}
		return classPreexisting, true
	}
	return s.class, false
}

func collect(path string, local map[netip.Addr]bool) (map[netip.Addr][]peerEvent, map[tupleKey]*tupleState, error) {
	events := map[netip.Addr][]peerEvent{}
	states := map[tupleKey]*tupleState{}
	err := readTrace(path, func(v hostguard.LiveEvent) error {
		if v.Kind != "frame" || v.ParseStatus != "ok" || v.Packet == nil || v.Packet.Proto != 6 {
			return nil
		}
		p := v.Packet
		src, dst := p.Src.Unmap(), p.Dst.Unmap()
		out := local[src]
		if out == local[dst] {
			return nil
		}
		k := tupleKey{netip.AddrPortFrom(dst, p.DPort), netip.AddrPortFrom(src, p.SPort)}
		if out {
			k = tupleKey{netip.AddrPortFrom(src, p.SPort), netip.AddrPortFrom(dst, p.DPort)}
		}
		class, start := classify(states, k, out, p.SYN && !p.ACK, p.Seq)
		e := peerEvent{at: p.TS.UTC().Truncate(time.Microsecond), class: class, start: start}
		switch class {
		case classLocal:
			e.port = k.peer.Port()
		case classPeer:
			e.port = k.local.Port()
		}
		if !out {
			e.inBytes = int64(p.IPTotal)
		}
		events[k.peer.Addr()] = append(events[k.peer.Addr()], e)
		return nil
	})
	return events, states, err
}

// window 汇总 (asOf-W, asOf] 内同对端按发起方的新连接数与入站字节；与引擎滑窗边界一致。
func window(list []peerEvent, asOf time.Time, seconds int) (starts, inBytes map[string]int64, ports map[uint16]int64) {
	starts, inBytes, ports = map[string]int64{}, map[string]int64{}, map[uint16]int64{}
	cut := asOf.Add(-time.Duration(seconds) * time.Second)
	i := sort.Search(len(list), func(i int) bool { return list[i].at.After(cut) })
	for ; i < len(list) && !list[i].at.After(asOf); i++ {
		e := list[i]
		if e.start {
			starts[e.class]++
			if e.port > 0 {
				ports[e.port]++
			}
		}
		inBytes[e.class] += e.inBytes
	}
	return
}

func contextValue(o hostguard.Observation, r rule) (float64, bool) {
	for _, x := range o.Contexts {
		if x.WindowSeconds != r.Window {
			continue
		}
		switch r.Field {
		case "peerFlowStarts":
			return float64(x.PeerFlowStarts), true
		case "peerBytesInbound":
			return float64(x.PeerBytesInbound), true
		case "peerDistinctServicePorts":
			return float64(x.PeerDistinctServicePorts), true
		}
	}
	return 0, false
}

type ruleStats struct {
	Hits, Reconciled, PeerInitiatedZero, CandidateKept int64
	ByObservationDirection                             map[string]int64
	ByObservationClass                                 map[string]int64
	ContributionByClass                                map[string]int64
	ServicePorts                                       map[uint16]int64
	connections, peers, buckets                        map[string]bool
}

func evaluate(c sessionConfig, path string, events map[netip.Addr][]peerEvent, tuples map[tupleKey]*tupleState) (map[string]any, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	stats := map[string]*ruleStats{}
	for _, r := range rules {
		stats[r.ID] = &ruleStats{ByObservationDirection: map[string]int64{}, ByObservationClass: map[string]int64{},
			ContributionByClass: map[string]int64{}, ServicePorts: map[uint16]int64{},
			connections: map[string]bool{}, peers: map[string]bool{}, buckets: map[string]bool{}}
	}
	var uploaded int64
	uploadedByClass := map[string]int64{}
	var first, last time.Time
	emit := func(v hostguard.Emission) error {
		o := v.Observation
		if o.Transport != "tcp" || o.Direction == "outbound" {
			return nil
		}
		uploaded++
		if first.IsZero() || o.AsOf.Before(first) {
			first = o.AsOf
		}
		if o.AsOf.After(last) {
			last = o.AsOf
		}
		k := tupleKey{v.Endpoints.Local, v.Endpoints.Peer}
		ownClass := classPreexisting
		if s := tuples[k]; s != nil {
			ownClass = s.class
		}
		uploadedByClass[ownClass]++
		list := events[k.peer.Addr()]
		asOf := o.AsOf.UTC().Truncate(time.Microsecond)
		for _, r := range rules {
			value, ok := contextValue(o, r)
			if !ok || value < r.Threshold {
				continue
			}
			s := stats[r.ID]
			s.Hits++
			s.ByObservationDirection[o.Direction]++
			s.ByObservationClass[ownClass]++
			s.connections[o.ParentConnectionID] = true
			s.peers[o.PeerKey] = true
			s.buckets[o.PeerKey+"/"+asOf.Truncate(30*time.Second).Format(time.RFC3339)] = true
			starts, inBytes, ports := window(list, asOf, r.Window)
			var mine, peer float64
			switch r.Field {
			case "peerFlowStarts":
				mine = float64(starts[classLocal] + starts[classPeer] + starts[classPreexisting])
				peer = float64(starts[classPeer])
				for class, n := range starts {
					s.ContributionByClass[class] += n
				}
				for port, n := range ports {
					s.ServicePorts[port] += n
				}
			case "peerBytesInbound":
				mine = float64(inBytes[classLocal] + inBytes[classPeer] + inBytes[classPreexisting])
				peer = float64(inBytes[classPeer])
				for class, n := range inBytes {
					s.ContributionByClass[class] += n
				}
			default:
				// 端口规则在本样本没有命中，不拆分。
				mine, peer = value, value
			}
			if mine == value {
				s.Reconciled++
			}
			if peer == 0 {
				s.PeerInitiatedZero++
			}
			// 候选口径 C1：观察须为 inbound，且上下文只计对端发起的连接。
			if o.Direction == "inbound" && peer >= r.Threshold {
				s.CandidateKept++
			}
		}
		return nil
	}
	e, err := hostguard.New(hostguard.Config{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID,
		CaptureScopeID: c.CaptureScopeID, Environment: c.Environment, KeyEpoch: c.KeyEpoch,
		PeerSecret: secret, LocalAddresses: c.LocalAddresses, Emit: emit})
	if err != nil {
		return nil, err
	}
	prevKind, prevAt := "", time.Time{}
	err = readTrace(path, func(v hostguard.LiveEvent) error {
		pk, pa := prevKind, prevAt
		prevKind, prevAt = v.Kind, v.At
		// 与现行采集一致：读出帧/缺口后的同刻 tick 不推进水位。
		if v.Kind == "tick" && (pk == "frame" || pk == "gap") && pa.Equal(v.At) {
			return nil
		}
		return e.ApplyLiveEvent(v)
	})
	if err != nil {
		return nil, err
	}
	hours := last.Sub(first).Hours()
	out := map[string]any{}
	for _, r := range rules {
		s := stats[r.ID]
		out[r.ID] = map[string]any{
			"family": r.Family, "condition": fmt.Sprintf("contexts.%d.%s >= %v", r.Window, r.Field, r.Threshold),
			"hitObservations": s.Hits, "distinctConnections": len(s.connections), "distinctPeers": len(s.peers),
			"peer30sBuckets": len(s.buckets), "hitsPerHour": round(float64(s.Hits) / hours),
			"reconciledWithEngine": s.Reconciled, "peerInitiatedZero": s.PeerInitiatedZero,
			"keptUnderCandidateC1": s.CandidateKept, "byObservationDirection": s.ByObservationDirection,
			"byObservationConnectionClass": s.ByObservationClass,
			"windowContributionByClass":    s.ContributionByClass, "windowServicePorts": topPorts(s.ServicePorts, 5),
		}
	}
	return map[string]any{"uploadedObservations": uploaded, "uploadedByConnectionClass": uploadedByClass,
		"spanHours": round(hours), "rules": out}, nil
}

func topPorts(m map[uint16]int64, n int) []map[string]int64 {
	type kv struct {
		port uint16
		n    int64
	}
	var all []kv
	for p, c := range m {
		all = append(all, kv{p, c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n || all[i].n == all[j].n && all[i].port < all[j].port })
	var r []map[string]int64
	for i := 0; i < len(all) && i < n; i++ {
		r = append(r, map[string]int64{"port": int64(all[i].port), "starts": all[i].n})
	}
	return r
}

func round(x float64) float64 { return float64(int64(x*100+0.5)) / 100 }
