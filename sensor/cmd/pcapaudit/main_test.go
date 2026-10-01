package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/extract"
	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// 派生抓包必须保留解析所需头部和线路长度，不能把传输层载荷带入输出。
func TestHeadersPreserveMetadataWithoutPayload(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, proto := range []uint8{6, 17, 1, 58, 99} {
			for _, vlan := range []bool{false, true} {
				for _, fragment := range []uint16{0, 1} {
					src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
					if ipv6 {
						src, dst = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
					}
					f := synth.Build(synth.Spec{TS: time.Unix(1, 0), Src: src, Dst: dst, SPort: 12345, DPort: 80, Proto: proto, Flags: synth.SYN, MSS: 1460, Payload: 200, VLAN: vlan, FragOffset: fragment}, 0)
					p, status := packet.ParseEthernet(f.Data, f.WireLen, f.TS)
					if status != packet.OK {
						t.Fatal(status)
					}
					clipped := headers(f.Data, p, status)
					if len(clipped) != len(f.Data)-200 {
						t.Fatalf("payload retained or header lost: proto=%d length=%d", proto, len(clipped))
					}
					got, st := packet.ParseEthernet(clipped, f.WireLen, f.TS)
					if st != status || !reflect.DeepEqual(p, got) {
						t.Fatalf("metadata changed: %v %+v %+v", st, p, got)
					}
				}
			}
		}
	}
}

// 已排序输入的头部裁剪不得改变 v4 特征、诊断或离线长度旁路。
func TestHeaderOnlyExtractionParity(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	var full, clipped []synth.Frame
	for i := 0; i < 110; i++ {
		for j, flags := range []uint8{synth.SYN, synth.ACK, synth.RST | synth.ACK} {
			f := synth.Build(synth.Spec{TS: time.Unix(int64(i), int64(j)*1000000), Src: src, Dst: dst, SPort: uint16(10000 + i), DPort: 80, Proto: 6, Flags: flags, MSS: 1460, Payload: j * 2000, ZeroLength: i%2 == 0}, 0)
			full = append(full, f)
			p, st := packet.ParseEthernet(f.Data, f.WireLen, f.TS)
			f.Data = headers(f.Data, p, st)
			clipped = append(clipped, f)
		}
	}
	var outputs, audits [2]bytes.Buffer
	var diagnostics [2]any
	for i, frames := range [][]synth.Frame{full, clipped} {
		path := filepath.Join(t.TempDir(), "input.pcap")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = synth.WritePcap(f, 65535, frames); err != nil {
			t.Fatal(err)
		}
		f.Close()
		d, err := extract.Run(path, &outputs[i], extract.Options{LocalAddrs: []netip.Addr{dst}, KeyBase: "parity", MTU: 1500, LabelAudit: &audits[i]})
		if err != nil {
			t.Fatal(err)
		}
		diagnostics[i] = d
	}
	if !bytes.Equal(outputs[0].Bytes(), outputs[1].Bytes()) || !bytes.Equal(audits[0].Bytes(), audits[1].Bytes()) || !reflect.DeepEqual(diagnostics[0], diagnostics[1]) {
		t.Fatal("header clipping changed extraction")
	}
}
