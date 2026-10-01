// pcapaudit 审核公开抓包的时间/链路/乱序与端点活动，可写出稳定排序、仅含头部的离线 PCAP。
// 原件只读；没有实时抓包、发送或攻击能力。派生文件保留 wire length；不保留任何载荷字节。
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/packet"
	"os"
	"sort"
	"time"
)

type frame struct {
	ts   time.Time
	wire int
	data []byte
}
type stats struct {
	Version       string           `json:"toolVersion"`
	Frames        int64            `json:"frames"`
	First         time.Time        `json:"firstPacketUtc"`
	Last          time.Time        `json:"lastPacketUtc"`
	Min           time.Time        `json:"minPacketUtc"`
	Max           time.Time        `json:"maxPacketUtc"`
	Reversed      int64            `json:"timestampReversals"`
	SynReversed   int64            `json:"synTimestampReversals"`
	Syn           int64            `json:"synPackets"`
	MaxBackstepNs int64            `json:"maxBackstepNs"`
	Parse         map[string]int64 `json:"parseStatus"`
	AttackMinute  map[string]int64 `json:"knownEndpointMinuteCounts"`
	EthernetOnly  bool             `json:"allInterfacesEthernet"`
	Sorted        bool             `json:"sortedHeadersWritten"`
}

// headers 依据解析出的头长截断，绝不复制载荷；不支持的报文只保留链路头用于拒绝计数。
func headers(data []byte, p packet.Packet, st packet.Status) []byte {
	n := min(14, len(data))
	off := 14
	if len(data) >= 14 {
		typ := binary.BigEndian.Uint16(data[12:14])
		for (typ == 0x8100 || typ == 0x88a8) && len(data) >= off+4 {
			typ = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
	}
	if st == packet.OK {
		n = off + p.IPHdr
		if !p.LaterFrag {
			switch p.Proto {
			case 6:
				n += p.TCPHdr
			case 17:
				n += 8
			case 1, 58:
				n += 8
			}
		}
	}
	return append([]byte(nil), data[:min(n, len(data))]...)
}
func run() error {
	in := flag.String("pcap", "", "只读原始文件")
	out := flag.String("sorted-headers", "", "可选：稳定排序头部 PCAP，必须不存在")
	report := flag.String("report", "", "汇总 JSON")
	flag.Parse()
	if *in == "" || *report == "" {
		return fmt.Errorf("须指定 pcap/report")
	}
	if *out == *in || *report == *in || (*out != "" && *out == *report) {
		return fmt.Errorf("路径必须不同")
	}
	if *out != "" {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("输出已存在")
		}
	}
	s := stats{Version: "pcap-audit-v1", Parse: map[string]int64{}, AttackMinute: map[string]int64{}}
	var frames []frame
	var prev, prevSyn time.Time
	err := capture.WalkFile(*in, func(data []byte, ci gopacket.CaptureInfo) error {
		ts := ci.Timestamp.UTC()
		s.Frames++
		if s.Frames == 1 {
			s.First = ts
			s.Min = ts
			s.Max = ts
		}
		s.Last = ts
		if ts.Before(s.Min) {
			s.Min = ts
		}
		if ts.After(s.Max) {
			s.Max = ts
		}
		if ts.Before(prev) {
			s.Reversed++
			if d := prev.Sub(ts).Nanoseconds(); d > s.MaxBackstepNs {
				s.MaxBackstepNs = d
			}
		}
		prev = ts
		p, st := packet.ParseEthernet(data, ci.Length, ts)
		s.Parse[st.String()]++
		if st == packet.OK && p.Proto == 6 && p.SYN && !p.ACK {
			s.Syn++
			if ts.Before(prevSyn) {
				s.SynReversed++
			}
			prevSyn = ts
		}
		// 只登记公开论文已给出的攻击端点/目的端口每分钟计数，不落盘任意背景地址。
		if st == packet.OK && p.Src.String() == "172.16.0.1" && (p.Dst.String() == "192.168.10.50" || p.Dst.String() == "192.168.10.51") {
			key := fmt.Sprintf("%s|%s|%d", ts.Format("2006-01-02T15:04Z"), p.Dst, p.DPort)
			s.AttackMinute[key]++
		}
		if *out != "" {
			frames = append(frames, frame{ts, ci.Length, headers(data, p, st)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.EthernetOnly = true
	if *out != "" {
		sort.SliceStable(frames, func(i, j int) bool { return frames[i].ts.Before(frames[j].ts) })
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		w := bufio.NewWriterSize(f, 1<<20)
		pw := pcapgo.NewWriterNanos(w)
		if err = pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			f.Close()
			return err
		}
		for _, fr := range frames {
			if err = pw.WritePacket(gopacket.CaptureInfo{Timestamp: fr.ts, CaptureLength: len(fr.data), Length: fr.wire}, fr.data); err != nil {
				f.Close()
				return err
			}
		}
		if err = w.Flush(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		s.Sorted = true
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*report, append(raw, '\n'), 0600)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
