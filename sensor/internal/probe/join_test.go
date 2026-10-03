package probe

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

const zeekHeader = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\tresp_pkts\ttunnel_parents   label   detailed-label\n"

func TestZeekMixedDelimiterAndInvalidInputs(t *testing.T) {
	row := "1.000001\tuid\t192.0.2.2\t30000\t192.0.2.3\t443\ttcp\t0.000002\t2\t1\t-   Malicious   DDoS\n"
	ls, err := Labels(strings.NewReader(zeekHeader+row), "public-scene")
	if err != nil || len(ls) != 1 {
		t.Fatalf("labels=%d err=%v", len(ls), err)
	}
	if ls[0].End.Sub(ls[0].Start) != 2*time.Microsecond || category(ls[0]) != "attack" {
		t.Fatal("微秒/标签语义丢失")
	}
	revision := strings.Replace(zeekHeader, "detailed-label", "det_label", 1)
	if revised, e := Labels(strings.NewReader(revision+row), "revised-scene"); e != nil || revised[0].Detail != "DDoS" || revised[0].DetailField != "det_label" {
		t.Fatal("发布者新版字段未明确兼容")
	}
	for _, bad := range []string{row + row, strings.Replace(row, "1.000001", "NaN", 1), strings.Replace(row, "0.000002", "-1", 1), strings.Replace(row, "\t2\t1\t", "\t-1\t1\t", 1)} {
		if _, err := Labels(strings.NewReader(zeekHeader+bad), "public-scene"); err == nil {
			t.Fatal("坏输入应拒绝")
		}
	}
	if _, err := Labels(strings.NewReader(row), "public-scene"); err == nil {
		t.Fatal("缺字段头应拒绝")
	}
}

func TestStratifiedSampleIncludesBothClassesWithoutDuplicates(t *testing.T) {
	var ls []Label
	for i := 0; i < 100; i++ {
		l := Label{ID: fmt.Sprintf("%03d", i), Label: "Malicious", Detail: "DDoS", Proto: "tcp", DurationKnown: true, RespPackets: 1}
		if i >= 80 {
			l.Label, l.Detail = "Benign", "-"
		}
		ls = append(ls, l)
	}
	ls = append(ls, Label{ID: "000-icmp", Label: "Benign", Detail: "-", Proto: "icmp"})
	sample := Sample(ls, 30)
	classes := map[string]int{}
	ids := map[string]bool{}
	for _, l := range sample {
		if ids[l.ID] {
			t.Fatal("样本重复")
		}
		ids[l.ID] = true
		classes[category(l)]++
	}
	tcpBenign := 0
	for _, l := range sample {
		if category(l) == "benign" && l.Proto == "tcp" {
			tcpBenign++
		}
	}
	if len(sample) != 30 || classes["attack"] < 10 || tcpBenign < 10 {
		t.Fatalf("分层错误: %v", classes)
	}
}

func TestReferenceDoesNotReadFuturePacketsAndProtocolNulls(t *testing.T) {
	t0 := time.Unix(10, 0)
	ps := []packetMeta{{p: packet.Packet{TS: t0, IPTotal: 40, SYN: true}, outbound: true}, {p: packet.Packet{TS: t0.Add(time.Millisecond), IPTotal: 60, SYN: true, ACK: true}}, {p: packet.Packet{TS: t0.Add(2 * time.Millisecond), IPTotal: 40, ACK: true}, outbound: true}, {p: packet.Packet{TS: t0.Add(6 * time.Second), IPTotal: 1500, RST: true}, outbound: true}}
	m := measure(ps, t0.Add(time.Second), true)
	if m.PacketsOutbound != 2 || m.BytesOutbound != 80 || m.LengthMax != 60 || m.RstCount == nil || *m.RstCount != 0 || !*m.HandshakeSeen {
		t.Fatalf("未来包污染或握手错误: %+v", m)
	}
	one := measure(ps[:1], t0, false)
	if one.IATMeanUs != nil || one.SynCount != nil || one.HandshakeSeen != nil || one.LengthStd != 0 {
		t.Fatal("单包/非 TCP 缺失语义错误")
	}
}

func TestPCAPJoinRejectsOverlappingConnectionLabelsAndTruncatedContainer(t *testing.T) {
	t0 := time.Unix(10, 0)
	host := netip.MustParseAddr("192.0.2.2")
	peer := netip.MustParseAddr("192.0.2.3")
	path := filepath.Join(t.TempDir(), "capture.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	frames := []synth.Frame{synth.Build(synth.Spec{TS: t0, Src: host, Dst: peer, SPort: 30000, DPort: 443, Proto: 6, Flags: synth.SYN}, 128)}
	if err = synth.WritePcap(f, 128, frames); err != nil {
		t.Fatal(err)
	}
	f.Close()
	l := Label{ID: "one", Label: "Malicious", Detail: "DDoS", Proto: "tcp", Origin: netip.AddrPortFrom(host, 30000), Responder: netip.AddrPortFrom(peer, 443), Start: t0, End: t0, OrigPackets: 1}
	r, err := Audit(path, []Label{l}, "scene", host, 30)
	if err != nil || r.Samples[0].Status != "matched" || !r.Samples[0].TargetConstructible {
		t.Fatalf("合法关联错误: %+v %v", r, err)
	}
	copy := l
	copy.ID = "two"
	r, err = Audit(path, []Label{l, copy}, "scene", host, 30)
	if err != nil || r.Samples[0].Status != "ambiguous" || r.Samples[0].TargetConstructible {
		t.Fatal("重叠标签应阻止执行目标证据")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Audit(path, []Label{l}, "scene", host, 30); err == nil {
		t.Fatal("截断容器不能输出成功审计")
	}
}
