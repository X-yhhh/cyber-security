// guardjoin 将已登记试点全部标签与完整原件关联；载荷仅在有界起点旁路读取，不进入特征。
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type label struct {
	ID            string         `json:"id"`
	Origin        netip.AddrPort `json:"origin"`
	Responder     netip.AddrPort `json:"responder"`
	Protocol      uint8          `json:"protocol"`
	Start         int64          `json:"start"`
	End           int64          `json:"end"`
	Label         string         `json:"label"`
	Overlaps      bool           `json:"overlaps"`
	FwdPackets    int64          `json:"fwdPackets"`
	BwdPackets    int64          `json:"bwdPackets"`
	FwdPayload    int64          `json:"fwdPayload"`
	BwdPayload    int64          `json:"bwdPayload"`
	observed      [4]int64
	first, last   int64
	firstSyn      bool
	syns          map[uint32]bool
	reverse       int
	bad           int
	offload       int
	expected      uint64
	request       []byte
	reviewError   string
	onset         *int64
	complete      *int64
	continuations int
}
type key struct {
	a, b  netip.AddrPort
	proto uint8
}

func tuple(a, b netip.AddrPort, p uint8) key {
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	return key{a, b, p}
}

// review 只识别已登记 CIC2017 的连续未完成 GET 后续 X-a: b；完整/部分重传不增加起点证据。
func (l *label) review(p hostguard.Packet, data []byte) {
	if l.Label != "DoS Slowloris" || l.reviewError != "" {
		return
	}
	if p.SYN && !p.ACK {
		if l.expected == 0 {
			l.expected = uint64(p.Seq) + 1
		}
		return
	}
	if p.PayloadBytes == 0 {
		return
	}
	if l.expected == 0 {
		l.reviewError = "missing_syn"
		return
	}
	off := 14
	if p.VLAN {
		off = 18
	}
	off += p.IPHdr + p.TCPHdr
	if off+p.PayloadBytes > len(data) {
		l.reviewError = "payload_truncated"
		return
	}
	if uint64(p.Seq) > l.expected {
		l.reviewError = "sequence_gap"
		return
	}
	skip := l.expected - uint64(p.Seq)
	if skip >= uint64(p.PayloadBytes) {
		return
	}
	novel := data[off+int(skip) : off+p.PayloadBytes]
	if len(l.request)+len(novel) > 32768 || l.expected+uint64(len(novel)) >= 1<<32 {
		l.reviewError = "review_bound_or_wrap"
		return
	}
	previous := len(l.request)
	l.request = append(l.request, novel...)
	l.expected += uint64(len(novel))
	at := p.TS.UnixMicro()
	if l.complete != nil {
		return
	}
	if bytes.Contains(l.request, []byte("\r\n\r\n")) {
		l.complete = &at
		return
	}
	lineEnd := bytes.Index(l.request, []byte("\r\n"))
	validGet := lineEnd > 0 && bytes.HasPrefix(l.request, []byte("GET ")) && (bytes.HasSuffix(l.request[:lineEnd], []byte(" HTTP/1.1")) || bytes.HasSuffix(l.request[:lineEnd], []byte(" HTTP/1.0")))
	if previous > 0 && validGet && bytes.Equal(novel, []byte("X-a: b\r\n")) {
		l.continuations++
		if l.onset == nil {
			l.onset = &at
		}
	}
}
func run() error {
	labels := flag.String("labels", "", "受控规范标签 JSONL")
	pcap := flag.String("pcap", "", "完整 PCAP")
	out := flag.String("out", "", "不存在的逐行关联 JSONL")
	flag.Parse()
	if *labels == "" || *pcap == "" || *out == "" {
		return fmt.Errorf("缺少 labels/pcap/out")
	}
	f, err := os.Open(*labels)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(bufio.NewReader(f))
	by := map[key][]*label{}
	var all []*label
	for {
		var l label
		err = d.Decode(&l)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if l.ID == "" || !l.Origin.IsValid() || !l.Responder.IsValid() || l.End < l.Start {
			return fmt.Errorf("标签无效")
		}
		l.syns = map[uint32]bool{}
		all = append(all, &l)
		k := tuple(l.Origin, l.Responder, l.Protocol)
		by[k] = append(by[k], &l)
	}
	for _, ls := range by {
		sort.Slice(ls, func(i, j int) bool { return ls[i].Start < ls[j].Start })
	}
	err = hostguard.WalkPCAP(*pcap, func(data []byte, ci gopacket.CaptureInfo, seq uint64) error {
		p, status := hostguard.Parse(data, ci.Length, ci.Timestamp, seq, 1500)
		if !p.Src.IsValid() || !p.Dst.IsValid() {
			return nil
		}
		a, b := netip.AddrPortFrom(p.Src, p.SPort), netip.AddrPortFrom(p.Dst, p.DPort)
		ls := by[tuple(a, b, p.Proto)]
		ts := p.TS.UnixMicro()
		for _, l := range ls {
			if l.Start > ts+1 {
				break
			}
			if ts > l.End+1 {
				continue
			}
			if status != "ok" {
				l.bad++
				continue
			}
			forward := a == l.Origin
			if l.first == 0 {
				l.first = ts
				l.firstSyn = forward && p.SYN && !p.ACK
			}
			if ts < l.last {
				l.reverse++
			}
			l.last = max(l.last, ts)
			if forward {
				l.observed[0]++
				l.observed[2] += int64(p.PayloadBytes)
				if p.SYN && !p.ACK {
					l.syns[p.Seq] = true
				}
				l.review(p, data)
			} else {
				l.observed[1]++
				l.observed[3] += int64(p.PayloadBytes)
			}
			if p.Quality.OffloadSuspected {
				l.offload++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	fout, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer fout.Close()
	w := bufio.NewWriterSize(fout, 1<<20)
	enc := json.NewEncoder(w)
	counts := map[string]int{}
	for _, l := range all {
		status := "matched"
		expected := [4]int64{l.FwdPackets, l.BwdPackets, l.FwdPayload, l.BwdPayload}
		if l.first == 0 {
			status = "unmatched"
		} else if l.Overlaps {
			status = "ambiguous"
		} else if l.observed != expected || l.bad > 0 {
			status = "inconsistent"
		}
		onsetOK := status == "matched" && l.firstSyn && len(l.syns) == 1 && l.reverse == 0 && l.offload == 0 && l.reviewError == "" && l.onset != nil
		row := map[string]any{"labelId": l.ID, "label": l.Label, "join": status, "expected": expected, "observed": l.observed, "synStart": l.firstSyn, "distinctSynSequences": len(l.syns), "timestampRegressions": l.reverse, "badHeaders": l.bad, "offloadPackets": l.offload, "onsetCandidateUs": l.onset, "headerCompleteUs": l.complete, "onsetStructuralChecksPassed": onsetOK, "reviewError": l.reviewError, "independentContinuations": l.continuations, "prefixSupervisionApproved": false}
		if err = enc.Encode(row); err != nil {
			return err
		}
		counts[status]++
	}
	if err = w.Flush(); err != nil {
		return err
	}
	if err = fout.Sync(); err != nil {
		return err
	}
	fmt.Printf("labels=%d joins=%v timestamp=%s\n", len(all), counts, time.Now().UTC().Format(time.RFC3339))
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardjoin:", err)
		os.Exit(1)
	}
}
