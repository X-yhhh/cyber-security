package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/pipeline"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

// 容器变化不能改变冻结特征：经典 pcap 与 pcapng 的完整记录、微秒时间和诊断必须一致。
func TestPcapngMatchesClassicCapture(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.2")
	peer := netip.MustParseAddr("192.0.2.3")
	var frames []synth.Frame
	for i := 0; i < 101; i++ {
		frames = append(frames, synth.Build(synth.Spec{TS: time.Unix(1700000000, int64(i)*1000000+123000).UTC(), Src: peer, Dst: host, SPort: uint16(20000 + i), DPort: 53, Proto: 17, Payload: 20}, 128))
	}
	classic := filepath.Join(t.TempDir(), "classic.pcap")
	f, err := os.Create(classic)
	if err != nil {
		t.Fatal(err)
	}
	if err = synth.WritePcap(f, 128, frames); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	ng := filepath.Join(t.TempDir(), "renamed.pcap") // 识别文件头，不能依赖后缀。
	writeNg(t, ng, frames, false)
	read := func(name string) ([]feature.Record, pipeline.Diagnostics) {
		var records []feature.Record
		p := pipeline.New(flow.NewTable(1500, 10000), feature.NewBuilder(feature.NewAddressPolicy([]netip.Addr{host}, nil), "parity"), func(rs []feature.Record) { records = append(records, rs...) })
		if err := ReadFile(name, p); err != nil {
			t.Fatal(err)
		}
		return records, p.Diagnostics()
	}
	a, da := read(classic)
	b, db := read(ng)
	if len(a) != 101 || !reflect.DeepEqual(a, b) || !reflect.DeepEqual(da, db) {
		t.Fatal("pcapng 改变了记录或诊断")
	}
}

// 混合链路文件不能静默跳过不支持的接口；截断容器也必须失败，不能把前缀视为完整数据集。
func TestPcapngRejectsMixedLinkAndTruncation(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.2")
	frame := synth.Build(synth.Spec{TS: time.Unix(1700000000, 0), Src: netip.MustParseAddr("192.0.2.3"), Dst: host, SPort: 20000, DPort: 53, Proto: 17, Payload: 20}, 128)
	for _, mixed := range []bool{false, true} {
		name := filepath.Join(t.TempDir(), "invalid.pcapng")
		writeNg(t, name, []synth.Frame{frame}, mixed)
		if !mixed {
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Truncate(name, info.Size()-3); err != nil {
				t.Fatal(err)
			}
		}
		p := pipeline.New(flow.NewTable(1500, 10000), feature.NewBuilder(feature.NewAddressPolicy([]netip.Addr{host}, nil), "test"), func([]feature.Record) {})
		if err := ReadFile(name, p); err == nil {
			t.Fatal("应拒绝混合链路或截断文件")
		}
	}
}

func writeNg(t *testing.T, name string, frames []synth.Frame, mixed bool) {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: frame.TS, CaptureLength: len(frame.Data), Length: frame.WireLen}, frame.Data); err != nil {
			t.Fatal(err)
		}
	}
	if mixed {
		id, err := w.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeRaw, SnapLength: 128})
		if err != nil {
			t.Fatal(err)
		}
		frame := frames[0]
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: frame.TS, InterfaceIndex: id, CaptureLength: len(frame.Data) - 14, Length: frame.WireLen - 14}, frame.Data[14:]); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// 新 section 会重置接口编号，仍须检查实际每包链路，不能只检查文件首个接口。
func TestPcapngRejectsNonEthernetLaterSection(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.2")
	frame := synth.Build(synth.Spec{TS: time.Unix(1700000000, 0), Src: netip.MustParseAddr("192.0.2.3"), Dst: host, SPort: 20000, DPort: 53, Proto: 17, Payload: 20}, 128)
	name := filepath.Join(t.TempDir(), "sections.pcapng")
	writeNg(t, name, []synth.Frame{frame}, false)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: frame.TS, CaptureLength: len(frame.Data) - 14, Length: frame.WireLen - 14}, frame.Data[14:]); err != nil {
		t.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(flow.NewTable(1500, 10000), feature.NewBuilder(feature.NewAddressPolicy([]netip.Addr{host}, nil), "test"), func([]feature.Record) {})
	if err = ReadFile(name, p); err == nil {
		t.Fatal("应拒绝后续非以太网 section")
	}
}

// 即使没有报文引用，声明过的非 Ethernet 接口也不符合本轮数据集登记门禁。
func TestPcapngRejectsUnusedNonEthernetInterface(t *testing.T) {
	for _, laterSection := range []bool{false, true} {
		name := filepath.Join(t.TempDir(), "unused-interface.pcapng")
		f, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeRaw, SnapLength: 128}); err != nil {
			t.Fatal(err)
		}
		if err = w.Flush(); err != nil {
			t.Fatal(err)
		}
		if laterSection {
			w, err = pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Flush(); err != nil {
				t.Fatal(err)
			}
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if err = WalkFile(name, func([]byte, gopacket.CaptureInfo) error { return nil }); err == nil {
			t.Fatal("未拒绝没有报文的非以太网接口")
		}
	}
}
