// Package probe 审查公开 Zeek 标签与原始包的可关联性；不是 v5 提取器，不生成训练或执行输入。
package probe

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/packet"
)

// Label 的端点只驻留审计进程内；报告只输出来源/UID 的摘要，不落盘地址或载荷。
type Label struct {
	ID, Label, Detail, Proto string
	DetailField              string
	Origin, Responder        netip.AddrPort
	Start, End               time.Time
	DurationKnown            bool
	OrigPackets, RespPackets int64
}

// Labels 验证 Zeek 字段和 IoT-23 的三空格标签尾部；缺列、坏值及重复 UID 均拒绝。
func Labels(r io.Reader, scenario string) ([]Label, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 1<<20)
	var fields []string
	var labels []Label
	seen := map[string]bool{}
	for line := 1; s.Scan(); line++ {
		text := s.Text()
		if strings.HasPrefix(text, "#separator") && text != "#separator \\x09" {
			return nil, fmt.Errorf("第 %d 行不是 TAB Zeek 格式", line)
		}
		if strings.HasPrefix(text, "#fields\t") {
			fields = strings.Fields(strings.TrimPrefix(text, "#fields\t"))
			continue
		}
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if len(fields) == 0 {
			return nil, fmt.Errorf("缺少 Zeek #fields")
		}
		reader := csv.NewReader(strings.NewReader(text))
		reader.Comma, reader.FieldsPerRecord, reader.LazyQuotes = '\t', -1, true
		row, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("第 %d 行格式错误", line)
		}
		// 发布文件将 tunnel_parents / label / detailed-label 放在一个 TAB 列内。
		if len(row) == len(fields)-2 {
			tail := strings.Fields(row[len(row)-1])
			if len(tail) == 3 {
				row = append(row[:len(row)-1], tail...)
			}
		}
		if len(row) != len(fields) {
			return nil, fmt.Errorf("第 %d 行列数不符", line)
		}
		values := map[string]string{}
		for i, name := range fields {
			values[name] = row[i]
		}
		if value, ok := values["det_label"]; ok {
			if _, duplicate := values["detailed-label"]; duplicate {
				return nil, fmt.Errorf("详细标签列重复")
			}
			values["detailed-label"] = value
			values["detail-field"] = "det_label"
		} else {
			values["detail-field"] = "detailed-label"
		}
		for _, name := range []string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration", "orig_pkts", "resp_pkts", "label", "detailed-label"} {
			if _, ok := values[name]; !ok {
				return nil, fmt.Errorf("缺少字段 %s", name)
			}
		}
		if seen[values["uid"]] {
			return nil, fmt.Errorf("第 %d 行 UID 重复", line)
		}
		seen[values["uid"]] = true
		l, err := parseLabel(values, scenario)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行: %w", line, err)
		}
		labels = append(labels, l)
	}
	return labels, s.Err()
}

func timestamp(value string) (time.Time, error) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 4102444800 {
		return time.Time{}, fmt.Errorf("时间不合法")
	}
	return time.Unix(0, int64(math.Round(seconds*1e6))*1000).UTC(), nil
}

func parseLabel(v map[string]string, scenario string) (Label, error) {
	l := Label{ID: Digest([]byte(scenario + "\x00" + v["uid"])), Label: v["label"], Detail: v["detailed-label"], Proto: v["proto"], DetailField: v["detail-field"]}
	var err error
	if l.Start, err = timestamp(v["ts"]); err != nil {
		return l, err
	}
	l.End = l.Start
	if v["duration"] != "-" {
		d, e := strconv.ParseFloat(v["duration"], 64)
		if e != nil || math.IsNaN(d) || math.IsInf(d, 0) || d < 0 || d > 7*86400 {
			return l, fmt.Errorf("时长不合法")
		}
		l.End, l.DurationKnown = l.Start.Add(time.Duration(math.Round(d*1e6))*time.Microsecond), true
	}
	for i, prefix := range []string{"orig", "resp"} {
		a, e := netip.ParseAddr(v["id."+prefix+"_h"])
		if e != nil {
			return l, fmt.Errorf("地址格式不合法")
		}
		p, e := strconv.ParseUint(v["id."+prefix+"_p"], 10, 16)
		if e != nil {
			return l, fmt.Errorf("端口格式不合法")
		}
		n, e := strconv.ParseInt(v[prefix+"_pkts"], 10, 64)
		if e != nil || n < 0 {
			return l, fmt.Errorf("报文数不合法")
		}
		if i == 0 {
			l.Origin, l.OrigPackets = netip.AddrPortFrom(a.Unmap(), uint16(p)), n
		} else {
			l.Responder, l.RespPackets = netip.AddrPortFrom(a.Unmap(), uint16(p)), n
		}
	}
	return l, nil
}

func Digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func FileHash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func category(l Label) string {
	if l.Label == "Malicious" {
		return "attack"
	}
	if l.Label == "Benign" && l.Detail == "-" {
		return "benign"
	}
	return "unknown"
}

// Sample 每个正负层至少取十条，按稳定摘要排序；其余覆盖缺时长、缺反向包和非 TCP 边界。
// 总量不足时保留真实数目，绝不重复一条连接补足样本。
func Sample(labels []Label, count int) []Label {
	ordered := append([]Label(nil), labels...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	chosen, used := []Label{}, map[string]bool{}
	add := func(l Label) { chosen = append(chosen, l); used[l.ID] = true }
	for _, class := range []string{"attack", "benign"} {
		n := 0
		for _, l := range ordered {
			if category(l) == class && (l.Proto == "tcp" || l.Proto == "udp") && n < 10 {
				add(l)
				n++
			}
		}
	}
	for _, l := range ordered {
		if len(chosen) >= count {
			break
		}
		if !used[l.ID] && (category(l) == "unknown" || !l.DurationKnown || l.RespPackets == 0 || l.Proto != "tcp") {
			add(l)
		}
	}
	for _, l := range ordered {
		if len(chosen) < count && !used[l.ID] {
			add(l)
		}
	}
	return chosen
}

type Metrics struct {
	PacketsOutbound int64    `json:"packetsOutbound"`
	PacketsInbound  int64    `json:"packetsInbound"`
	BytesOutbound   int64    `json:"bytesOutbound"`
	BytesInbound    int64    `json:"bytesInbound"`
	LengthMin       int      `json:"lengthMin"`
	LengthMax       int      `json:"lengthMax"`
	LengthMean      float64  `json:"lengthMean"`
	LengthStd       float64  `json:"lengthStd"`
	IATMeanUs       *float64 `json:"iatMeanUs"`
	IATStdUs        *float64 `json:"iatStdUs"`
	SynCount        *int64   `json:"synCount"`
	SynAckCount     *int64   `json:"synAckCount"`
	RstCount        *int64   `json:"rstCount"`
	FinCount        *int64   `json:"finCount"`
	HandshakeSeen   *bool    `json:"handshakeSeen"`
}

type packetMeta struct {
	p        packet.Packet
	seq      int64
	outbound bool
}
type window struct {
	name  string
	until time.Time
}

// Measure 是采样包的头部参考计算，仅使用截止点之前的包；不替代 P2 的水位、流 epoch 或上下文。
func measure(packets []packetMeta, until time.Time, tcp bool) Metrics {
	m := Metrics{}
	var n int64
	var sum, sumSq, iatSum, iatSq float64
	var prev time.Time
	var syn, synAck, rst, fin int64
	handshake, state := false, 0
	var initiatorOutbound bool
	for _, pm := range packets {
		p := pm.p
		if p.TS.After(until) {
			continue
		}
		if pm.outbound {
			m.PacketsOutbound++
			m.BytesOutbound += int64(p.IPTotal)
		} else {
			m.PacketsInbound++
			m.BytesInbound += int64(p.IPTotal)
		}
		if n == 0 || p.IPTotal < m.LengthMin {
			m.LengthMin = p.IPTotal
		}
		if p.IPTotal > m.LengthMax {
			m.LengthMax = p.IPTotal
		}
		if n > 0 {
			d := float64(p.TS.Sub(prev).Nanoseconds()) / 1000
			iatSum += d
			iatSq += d * d
		}
		prev, n = p.TS, n+1
		sum += float64(p.IPTotal)
		sumSq += float64(p.IPTotal) * float64(p.IPTotal)
		if tcp {
			if p.SYN && !p.ACK {
				syn++
				if state == 0 {
					state, initiatorOutbound = 1, pm.outbound
				}
			}
			if p.SYN && p.ACK {
				synAck++
				if state == 1 && pm.outbound != initiatorOutbound {
					state = 2
				}
			}
			if p.ACK && !p.SYN && state == 2 && pm.outbound == initiatorOutbound {
				handshake = true
			}
			if p.RST {
				rst++
			}
			if p.FIN {
				fin++
			}
		}
	}
	if n > 0 {
		m.LengthMean = sum / float64(n)
		m.LengthStd = math.Sqrt(math.Max(0, sumSq/float64(n)-m.LengthMean*m.LengthMean))
	}
	if n > 1 {
		mean := iatSum / float64(n-1)
		std := math.Sqrt(math.Max(0, iatSq/float64(n-1)-mean*mean))
		m.IATMeanUs, m.IATStdUs = &mean, &std
	}
	if tcp {
		m.SynCount, m.SynAckCount, m.RstCount, m.FinCount, m.HandshakeSeen = &syn, &synAck, &rst, &fin, &handshake
	}
	return m
}

type SampleResult struct {
	ID                  string             `json:"connectionDigest"`
	Class               string             `json:"class"`
	Detail              string             `json:"publisherDetailedLabel"`
	Protocol            string             `json:"protocol"`
	Status              string             `json:"joinStatus"`
	ExpectedPackets     int64              `json:"publisherPackets"`
	ObservedPackets     int64              `json:"observedPackets"`
	OrigCountMatches    bool               `json:"originatorCountMatches"`
	RespCountMatches    bool               `json:"responderCountMatches"`
	StartDeltaUs        *int64             `json:"startDeltaUs"`
	Direction           string             `json:"direction"`
	TargetConstructible bool               `json:"targetMetadataConstructible"`
	LabelScope          string             `json:"labelScope"`
	Quality             map[string]int64   `json:"quality"`
	Reference           map[string]Metrics `json:"headerReference"`
}

type Report struct {
	Version                    string            `json:"toolVersion"`
	BinaryHash                 string            `json:"toolBinarySha256"`
	ContractProfileHash        string            `json:"contractProfileSha256"`
	Environment                map[string]string `json:"environment"`
	SamplingPolicy             string            `json:"samplingPolicy"`
	DetailedLabelField         string            `json:"publisherDetailedLabelField"`
	ZeroPacketLabels           map[string]int64  `json:"publisherZeroPacketCounts"`
	Scenario                   string            `json:"scenario"`
	PCAPHash                   string            `json:"pcapSha256"`
	PCAPBytes                  int64             `json:"pcapBytes"`
	LabelHash                  string            `json:"labelSha256"`
	LabelBytes                 int64             `json:"labelBytes"`
	AnchorHash                 string            `json:"localAddressSha256"`
	LabelCount                 int               `json:"labelConnections"`
	Distribution               map[string]int64  `json:"publisherLabelDistribution"`
	Frames                     int64             `json:"frames"`
	ParseStatus                map[string]int64  `json:"parseStatus"`
	TimestampReversals         int64             `json:"timestampReversals"`
	MaxBackstepUs              int64             `json:"maxBackstepUs"`
	Samples                    []SampleResult    `json:"samples"`
	JoinGate                   string            `json:"sampleJoinGate"`
	ResearchOnly               bool              `json:"researchOnly"`
	HistoricalCaptureDropCount *int64            `json:"historicalCaptureDropCount"`
}

// Audit 用五元组、微秒起止时间和方向计数审查样本；重叠标签及坏包不能成为通过证据。
// 容器读取失败返回错误，不发布部分报告。原始标签不用于模型或动作决策。
func Audit(path string, labels []Label, scenario string, local netip.Addr, count int) (Report, error) {
	r := Report{Version: "p1-join-audit-v1", Scenario: scenario, AnchorHash: Digest([]byte(local.String())), LabelCount: len(labels), Distribution: map[string]int64{}, ZeroPacketLabels: map[string]int64{}, ParseStatus: map[string]int64{}, ResearchOnly: true, SamplingPolicy: "tcp_udp_10_attack_10_benign_then_10_boundaries_sha256_order_tolerance_1ms_mtu_1500"}
	if len(labels) > 0 {
		r.DetailedLabelField = labels[0].DetailField
	}
	for _, l := range labels {
		r.Distribution[l.Label+"/"+l.Detail]++
		if l.OrigPackets+l.RespPackets == 0 {
			r.ZeroPacketLabels[l.Label+"/"+l.Detail]++
		}
	}
	samples := Sample(labels, count)
	packets := make([][]packetMeta, len(samples))
	quality := make([]map[string]int64, len(samples))
	for i := range quality {
		quality[i] = map[string]int64{}
	}
	var prev time.Time
	err := capture.WalkFile(path, func(data []byte, ci gopacket.CaptureInfo) error {
		r.Frames++
		if !prev.IsZero() && ci.Timestamp.Before(prev) {
			r.TimestampReversals++
			r.MaxBackstepUs = max(r.MaxBackstepUs, prev.Sub(ci.Timestamp).Microseconds())
		}
		prev = ci.Timestamp
		p, st := packet.ParseEthernet(data, ci.Length, ci.Timestamp.UTC())
		r.ParseStatus[st.String()]++
		if st != packet.OK || p.LaterFrag {
			return nil
		}
		proto := map[uint8]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}[p.Proto]
		for i, l := range samples {
			if proto != l.Proto || p.TS.Before(l.Start.Add(-time.Millisecond)) || p.TS.After(l.End.Add(time.Millisecond)) {
				continue
			}
			forward := p.Src == l.Origin.Addr() && p.Dst == l.Responder.Addr() && p.SPort == l.Origin.Port() && p.DPort == l.Responder.Port()
			backward := p.Dst == l.Origin.Addr() && p.Src == l.Responder.Addr() && p.DPort == l.Origin.Port() && p.SPort == l.Responder.Port()
			if !forward && !backward {
				continue
			}
			if p.TotalFromCap || p.TCPOptTrunc || (p.Proto == 6 && p.IPTotal < p.IPHdr+p.TCPHdr) || (p.Proto == 17 && p.IPTotal < p.IPHdr+8) || (p.Proto == 17 && len(data) < p.IPHdr+14+8) {
				quality[i]["requiredHeaderInvalid"]++
			}
			if p.IPTotal > 1500 && !p.FirstFrag {
				quality[i]["offloadSuspected"]++
			}
			if p.FirstFrag {
				quality[i]["fragmented"]++
			}
			if p.Src != local && p.Dst != local {
				quality[i]["outsideLocalAnchor"]++
			}
			packets[i] = append(packets[i], packetMeta{p, r.Frames, p.Src == local})
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	good := map[string]int{}
	for i, l := range samples {
		ps := packets[i]
		sort.SliceStable(ps, func(a, b int) bool {
			return ps[a].p.TS.Before(ps[b].p.TS) || ps[a].p.TS.Equal(ps[b].p.TS) && ps[a].seq < ps[b].seq
		})
		s := SampleResult{ID: l.ID, Class: category(l), Detail: l.Detail, Protocol: l.Proto, ExpectedPackets: l.OrigPackets + l.RespPackets, ObservedPackets: int64(len(ps)), Status: "unmatched", Direction: "unknown", LabelScope: "final_only", Quality: quality[i], Reference: map[string]Metrics{}}
		if l.Proto != "tcp" && l.Proto != "udp" {
			s.Status = "unsupported_protocol"
		}
		if len(ps) > 0 {
			delta := ps[0].p.TS.Sub(l.Start).Microseconds()
			s.StartDeltaUs = &delta
			var orig, resp int64
			for _, pm := range ps {
				if pm.p.Src == l.Origin.Addr() && pm.p.SPort == l.Origin.Port() {
					orig++
				} else {
					resp++
				}
			}
			s.OrigCountMatches, s.RespCountMatches = orig == l.OrigPackets, resp == l.RespPackets
			s.Status = "matched"
			if !s.OrigCountMatches || !s.RespCountMatches || len(s.Quality) > 0 || delta < -1000 || delta > 1000 {
				s.Status = "inconsistent"
			}
			// 同五元组标签时间窗相交时，不能把一个包当成两个连接的确定证据。
			for _, other := range labels {
				if other.ID != l.ID && sameTuple(l, other) && !other.Start.After(l.End.Add(time.Millisecond)) && !l.Start.After(other.End.Add(time.Millisecond)) {
					s.Status = "ambiguous"
					break
				}
			}
			first := ps[0].p
			if l.Proto == "tcp" && first.SYN && !first.ACK && (first.Src == local || first.Dst == local) {
				s.Direction = "inbound"
				if first.Src == local {
					s.Direction = "outbound"
				}
				s.TargetConstructible = first.AF == 4 && len(s.Quality) == 0 && s.Status == "matched" && first.DPort > 0
			}
			for _, w := range []window{{"at_1s", l.Start.Add(time.Second)}, {"at_5s", l.Start.Add(5 * time.Second)}, {"final_reference", ps[len(ps)-1].p.TS}} {
				s.Reference[w.name] = measure(ps, w.until, l.Proto == "tcp")
			}
		}
		if s.Status == "matched" {
			good[s.Class]++
		}
		r.Samples = append(r.Samples, s)
	}
	r.JoinGate = "insufficient"
	if len(r.Samples) >= 30 && good["attack"] >= 10 && good["benign"] >= 10 {
		r.JoinGate = "passed_sample_only"
	}
	return r, nil
}

func sameTuple(a, b Label) bool {
	return a.Proto == b.Proto && (a.Origin == b.Origin && a.Responder == b.Responder || a.Origin == b.Responder && a.Responder == b.Origin)
}
