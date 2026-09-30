package anon

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/pipeline"
	"github.com/xyh/cyber-security/sensor/internal/synth"
)

var (
	t0     = time.Date(2026, 9, 30, 8, 15, 42, 123456000, time.UTC)
	subnet = netip.MustParsePrefix("10.1.2.0/24")
	local  = netip.MustParseAddr("10.1.2.40")
	gw     = netip.MustParseAddr("10.1.2.1")
	ext    = netip.MustParseAddr("203.0.113.5")
	local6 = netip.MustParseAddr("2001:db8:77::40")
)

func newAnon(t *testing.T) *Anonymizer {
	t.Helper()
	a, err := New(Options{Subnet: subnet, LocalV6: []netip.Addr{local6}, Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMapPreservesClassification(t *testing.T) {
	a := newAnon(t)
	cases := map[string]string{
		"10.1.2.40": "192.0.2.40", "10.1.2.1": "192.0.2.1", "10.1.2.255": "192.0.2.255",
		"255.255.255.255": "255.255.255.255", "224.0.0.251": "224.0.0.251", "127.0.0.1": "127.0.0.1",
		"2001:db8:77::40": "2001:db8::2", "ff02::fb": "ff02::fb",
	}
	for in, want := range cases {
		if got := a.Map(netip.MustParseAddr(in)); got.String() != want {
			t.Errorf("Map(%s)=%s want %s", in, got, want)
		}
	}
	e1, e2 := a.Map(ext), a.Map(netip.MustParseAddr("198.51.100.9"))
	if e1 == e2 || !netip.MustParsePrefix("198.18.0.0/15").Contains(e1) || a.Map(ext) != e1 {
		t.Fatalf("外部地址映射应单射且稳定: %s %s", e1, e2)
	}
	if ll := a.Map(netip.MustParseAddr("fe80::1234:1")); !ll.IsLinkLocalUnicast() {
		t.Fatalf("链路本地应仍为链路本地: %s", ll)
	}
	if sol := a.Map(netip.MustParseAddr("ff02::1:ff12:3456")); !sol.IsMulticast() || sol.String() == "ff02::1:ff12:3456" {
		t.Fatalf("被请求节点多播应改写且仍为多播: %s", sol)
	}
}

// frames 构造 120 条入站 DNS 流、一次带 MSS 的 TCP 握手、一条定向广播和一条外部流；
// 载荷写入非零字节，用于验证不被保留。时间互不相同，避免排序依赖流键。
func frames() []synth.Frame {
	var fs []synth.Frame
	add := func(s synth.Spec) {
		f := synth.Build(s, 128)
		for i := len(f.Data) - s.Payload; i < len(f.Data) && s.Payload > 0; i++ {
			f.Data[i] = 0xab
		}
		fs = append(fs, f)
	}
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	for i := 0; i < 120; i++ {
		peer := netip.AddrFrom4([4]byte{10, 1, 2, byte(50 + i%4)})
		if i%3 == 0 {
			peer = ext
		}
		add(synth.Spec{TS: at(i * 97), Src: peer, Dst: local, SPort: uint16(40000 + i), DPort: 53, Proto: 17, Payload: 30})
		add(synth.Spec{TS: at(i*97 + 3), Src: local, Dst: peer, SPort: 53, DPort: uint16(40000 + i), Proto: 17, Payload: 60})
	}
	add(synth.Spec{TS: at(20_000), Src: gw, Dst: local, SPort: 50000, DPort: 22, Proto: 6, Flags: synth.SYN, MSS: 1460})
	add(synth.Spec{TS: at(20_020), Src: local, Dst: gw, SPort: 22, DPort: 50000, Proto: 6, Flags: synth.SYN | synth.ACK, MSS: 1400})
	add(synth.Spec{TS: at(20_045), Src: gw, Dst: local, SPort: 50000, DPort: 22, Proto: 6, Flags: synth.ACK | synth.PSH, Payload: 50})
	add(synth.Spec{TS: at(21_000), Src: local, Dst: netip.MustParseAddr("10.1.2.255"), SPort: 137, DPort: 137, Proto: 17, Payload: 40})
	add(synth.Spec{TS: at(22_000), Src: local6, Dst: netip.MustParseAddr("2001:db8:99::1"), SPort: 51000, DPort: 443, Proto: 6, Flags: synth.SYN, MSS: 1440})
	return fs
}

func extract(fs []synth.Frame, locals []netip.Addr, sub netip.Prefix) ([]string, map[string]int64) {
	var out []string
	p := pipeline.New(flow.NewTable(1500, 10_000),
		feature.NewBuilder(feature.NewAddressPolicy(locals, []netip.Prefix{sub}), "t"),
		func(rs []feature.Record) {
			for _, r := range rs {
				b, _ := json.Marshal([]any{r.Status, r.Reason, r.AF, r.Viewpoint, r.HandshakeSeen, r.CloseReason, r.Features})
				out = append(out, string(b))
			}
		})
	for _, f := range fs {
		p.Frame(f.Data, f.WireLen, f.TS)
	}
	p.Close()
	sort.Strings(out)
	return out, p.Diagnostics().Feature.Excluded
}

func TestRewriteKeepsFeaturesAndDropsPayload(t *testing.T) {
	raw := frames()
	a := newAnon(t)
	var anon []synth.Frame
	for _, f := range raw {
		data, ts := a.Rewrite(f.Data, f.WireLen, f.TS)
		if bytes.Contains(data, []byte{0xab, 0xab}) {
			t.Fatal("假名化后仍含载荷字节")
		}
		if bytes.Contains(data, local.AsSlice()) || bytes.Contains(data, ext.AsSlice()) {
			t.Fatal("假名化后仍含原始地址")
		}
		anon = append(anon, synth.Frame{TS: ts, Data: data, WireLen: f.WireLen})
	}
	if !anon[0].TS.Equal(time.Date(2026, 10, 1, 0, 0, 0, 123456000, time.UTC)) {
		t.Fatalf("时间应平移到起点且保留微秒: %v", anon[0].TS)
	}
	want, wantEx := extract(raw, []netip.Addr{local, local6}, subnet)
	got, gotEx := extract(anon, []netip.Addr{a.Map(local), a.Map(local6)}, netip.MustParsePrefix("192.0.2.0/24"))
	if len(want) != len(got) || len(want) < 100 {
		t.Fatalf("记录数不一致: %d vs %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("第 %d 条特征不一致:\n原始 %s\n假名 %s", i, want[i], got[i])
		}
	}
	if len(wantEx) != len(gotEx) || wantEx["broadcast_destination"] != 1 || gotEx["broadcast_destination"] != 1 {
		t.Fatalf("排除计数不一致: %v vs %v", wantEx, gotEx)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, o := range []Options{{Subnet: netip.MustParsePrefix("10.1.0.0/16"), Start: start},
		{Subnet: subnet}, {Subnet: subnet, Start: start, LocalV6: []netip.Addr{local}}} {
		if _, err := New(o); err == nil {
			t.Fatalf("应拒绝: %+v", o)
		}
	}
}
