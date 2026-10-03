// guardgolden 生成/核对仅含文档保留地址的小型包级 golden；绝不打开网卡。
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

type event struct {
	Kind  string    `json:"kind"`
	At    time.Time `json:"at"`
	Frame string    `json:"frameHex,omitempty"`
	Wire  int       `json:"wireLength,omitempty"`
}
type scenario struct {
	Name     string  `json:"name"`
	Local    string  `json:"local"`
	MaxFlows int     `json:"maxFlows,omitempty"`
	Events   []event `json:"events"`
}

var origin = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

func frame(ms int, out bool, proto, flags uint8, size int, seq, ack uint32) event {
	a, b := netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("192.0.2.1")
	ap, bp := uint16(40000), uint16(80)
	if out {
		a, b = b, a
		ap, bp = bp, ap
	}
	f := synth.Build(synth.Spec{TS: origin.Add(time.Duration(ms) * time.Millisecond), Src: a, Dst: b, SPort: ap, DPort: bp, Proto: proto, Flags: flags, Payload: size}, 256)
	if proto == 6 {
		binary.BigEndian.PutUint32(f.Data[38:42], seq)
		binary.BigEndian.PutUint32(f.Data[42:46], ack)
	}
	return event{"frame", f.TS, hex.EncodeToString(f.Data), f.WireLen}
}
func tick(ms int) event {
	return event{Kind: "tick", At: origin.Add(time.Duration(ms) * time.Millisecond)}
}
func cases() []scenario {
	syn := frame(0, false, 6, 2, 0, 100, 0)
	s := []scenario{
		{Name: "single_packet", Events: []event{syn}},
		{Name: "handshake_bidirectional", Events: []event{syn, frame(10, true, 6, 18, 0, 500, 101), frame(20, false, 6, 16, 0, 101, 501), frame(1000, false, 6, 16, 50, 101, 501), tick(1100), frame(2000, true, 6, 16, 100, 501, 151), tick(5100)}},
		{Name: "missing_syn", Events: []event{frame(0, false, 6, 16, 10, 100, 0), tick(1100)}},
		{Name: "udp_null", Events: []event{frame(0, false, 17, 0, 8, 0, 0), frame(1000, true, 17, 0, 16, 0, 0), tick(1100)}},
		{Name: "same_timestamp", Events: []event{syn, frame(1000, false, 6, 16, 10, 101, 0), frame(1000, true, 6, 16, 20, 500, 0), tick(1100)}},
		{Name: "bounded_reorder", Events: []event{syn, frame(1000, false, 6, 16, 10, 101, 0), frame(950, true, 6, 16, 20, 500, 0), tick(1100)}},
		{Name: "late_packet", Events: []event{syn, tick(1100), frame(500, true, 6, 16, 20, 500, 0), frame(2000, false, 6, 16, 10, 101, 0), tick(5100)}},
		{Name: "gap", Events: []event{syn, {Kind: "gap", At: origin.Add(500 * time.Millisecond)}, frame(1000, false, 6, 16, 10, 101, 0), tick(1100)}},
		{Name: "syn_retransmit", Events: []event{syn, frame(100, false, 6, 2, 0, 100, 0), tick(1100)}},
		{Name: "rst_boundary", Events: []event{syn, frame(1000, true, 6, 20, 0, 500, 101), tick(1100), frame(2000, false, 6, 16, 0, 101, 0)}},
		{Name: "fin_both", Events: []event{syn, frame(800, true, 6, 17, 0, 500, 101), frame(1000, false, 6, 17, 0, 101, 501), tick(1100)}},
		{Name: "idle_continuation", Events: []event{syn, tick(30100), frame(31000, false, 6, 16, 10, 101, 0), tick(32100)}},
		{Name: "new_syn", Events: []event{syn, frame(500, false, 6, 2, 0, 800, 0), tick(1600)}},
		{Name: "offload", Events: []event{syn, frame(500, false, 6, 16, 2000, 101, 0), tick(1100)}},
	}
	trunc := frame(500, false, 6, 16, 0, 101, 0)
	trunc.Frame = trunc.Frame[:100]
	s = append(s, scenario{Name: "truncated", Events: []event{syn, trunc, frame(1000, false, 6, 16, 0, 101, 0), tick(1100)}})
	frag := frame(500, false, 6, 16, 0, 101, 0)
	b, _ := hex.DecodeString(frag.Frame)
	b[20] = 0x20
	frag.Frame = hex.EncodeToString(b)
	s = append(s, scenario{Name: "fragment", Events: []event{syn, frag, frame(1000, false, 6, 16, 0, 101, 0), tick(1100)}})
	other := frame(500, false, 6, 2, 0, 100, 0)
	b, _ = hex.DecodeString(other.Frame)
	binary.BigEndian.PutUint16(b[34:36], 40001)
	other.Frame = hex.EncodeToString(b)
	s = append(s, scenario{Name: "capacity", MaxFlows: 1, Events: []event{syn, other, tick(1100)}})
	maxLife := scenario{Name: "max_lifetime"}
	for i := 0; i <= 13; i++ {
		flags := uint8(16)
		if i == 0 {
			flags = 2
		}
		maxLife.Events = append(maxLife.Events, frame(i*10000, false, 6, flags, 0, 100, 0))
	}
	s = append(s, maxLife)
	rounding := scenario{Name: "floating_point_rounding"}
	for i := 0; i < 64; i++ {
		flags := uint8(16)
		if i == 0 {
			flags = 2
		}
		rounding.Events = append(rounding.Events, frame(i*127+i%3, i%2 == 1, 6, flags, (i*137+17)%1300, uint32(100+i*1400), 0))
	}
	s = append(s, rounding)
	v6 := synth.Build(synth.Spec{TS: origin, Src: netip.MustParseAddr("2001:db8::2"), Dst: netip.MustParseAddr("2001:db8::1"), SPort: 40000, DPort: 443, Proto: 17, Payload: 10}, 256)
	s = append(s, scenario{Name: "ipv6", Local: "2001:db8::1", Events: []event{{"frame", origin, hex.EncodeToString(v6.Data), v6.WireLen}, tick(1100)}})
	for i := range s {
		if s[i].Local == "" {
			s[i].Local = "192.0.2.1"
		}
	}
	return s
}
func generate() (map[string][]byte, error) {
	s := cases()
	inputs, _ := json.MarshalIndent(s, "", "  ")
	var output, reference, packets bytes.Buffer
	reference.WriteString("scenario\tfirstUs\tasOfUs\tlastUs\tpacketsOut\tpacketsIn\tbytesOut\tbytesIn\tlengthMin\tlengthMax\tlengthMean\tlengthStd\tiatMeanUs\tiatStdUs\n")
	packets.WriteString("scenario\tcaptureSeq\tatUs\toutbound\tipLength\n")
	count := 0
	for _, c := range s {
		e, err := hostguard.New(hostguard.Config{AssetID: "00000000-0000-4000-8000-000000000001", SensorID: "00000000-0000-4000-8000-000000000002", BootID: "00000000-0000-4000-8000-000000000003", CaptureScopeID: "00000000-0000-4000-8000-000000000004", Environment: "research", KeyEpoch: 1, PeerSecret: []byte("public-synthetic-golden-key-not-a-credential"), LocalAddresses: []netip.Addr{netip.MustParseAddr(c.Local)}, MaxFlows: c.MaxFlows, Emit: func(v hostguard.Emission) error {
			count++
			o := v.Observation
			f := o.Features
			_ = json.NewEncoder(&output).Encode(map[string]any{"scenario": c.Name, "observation": o})
			// Java 参考只取不含丢弃/重组的独立统计场景；复杂时序由手写 Go 断言覆盖。
			if referenceCase(c.Name) {
				fmt.Fprintf(&reference, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.17g\t%.17g\t%s\t%s\n", c.Name, o.FirstSeenAt.UnixMicro(), o.AsOf.UnixMicro(), o.LastPacketAt.UnixMicro(), f.PacketsOutbound, f.PacketsInbound, f.BytesOutbound, f.BytesInbound, f.LengthMin, f.LengthMax, f.LengthMean, f.LengthStd, number(f.IATMeanUs), number(f.IATStdUs))
			}
			return nil
		}})
		if err != nil {
			return nil, err
		}
		var seq uint64
		for _, v := range c.Events {
			switch v.Kind {
			case "frame":
				seq++
				b, err := hex.DecodeString(v.Frame)
				if err != nil {
					return nil, err
				}
				if referenceCase(c.Name) {
					p, status := hostguard.Parse(b, v.Wire, v.At, seq, 1500)
					if status != "ok" {
						return nil, fmt.Errorf("参考场景解析失败")
					}
					fmt.Fprintf(&packets, "%s\t%d\t%d\t%t\t%d\n", c.Name, seq, v.At.UnixMicro(), p.Src.String() == c.Local, p.IPTotal)
				}
				err = e.Frame(b, v.Wire, v.At, seq)
				if err != nil {
					return nil, err
				}
			case "tick":
				if err = e.Tick(v.At); err != nil {
					return nil, err
				}
			case "gap":
				if err = e.Gap(v.At); err != nil {
					return nil, err
				}
			}
		}
		if err = e.Close(); err != nil {
			return nil, err
		}
	}
	fmt.Printf("scenarios=%d observations=%d\n", len(s), count)
	return map[string][]byte{"cases.json": append(inputs, '\n'), "observations.jsonl": output.Bytes(), "reference.tsv": reference.Bytes(), "packets.tsv": packets.Bytes()}, nil
}
func number(p *float64) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprintf("%.17g", *p)
}
func referenceCase(name string) bool {
	switch name {
	case "single_packet", "handshake_bidirectional", "missing_syn", "udp_null", "same_timestamp", "bounded_reorder", "syn_retransmit", "offload", "ipv6", "floating_point_rounding":
		return true
	}
	return false
}
func run() error {
	dir := flag.String("dir", "testdata/hostguard-v5", "golden 目录")
	check := flag.Bool("check", false, "只校验，不改写冻结样本")
	flag.Parse()
	files, err := generate()
	if err != nil {
		return err
	}
	if !*check {
		if err = os.MkdirAll(*dir, 0755); err != nil {
			return err
		}
	}
	for name, b := range files {
		p := filepath.Join(*dir, name)
		if *check {
			old, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !bytes.Equal(b, old) {
				return fmt.Errorf("golden 不一致: %s", name)
			}
		} else {
			if err = os.WriteFile(p, b, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
