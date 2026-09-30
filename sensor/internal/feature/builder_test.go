package feature

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/flow"
)

var (
	t0     = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	host   = netip.MustParseAddr("192.0.2.2")
	peerA  = netip.MustParseAddr("192.0.2.10")
	peerB  = netip.MustParseAddr("192.0.2.11")
	remote = netip.MustParseAddr("198.51.100.7")
)

func policy() *AddressPolicy {
	return NewAddressPolicy([]netip.Addr{host}, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")})
}

// udp 构造一条已完成的 UDP 流：init → resp:port，结束于 t0 + endMs。
func udp(seq int64, init, resp netip.Addr, port uint16, endMs int, spkts, sbytes int64) flow.Completed {
	end := t0.Add(time.Duration(endMs) * time.Millisecond)
	f := &flow.Flow{Key: flow.Key{Proto: 17}, AF: 4, Init: flow.Endpoint{Addr: init, Port: 5000},
		Resp: flow.Endpoint{Addr: resp, Port: port}, Start: end.Add(-500 * time.Millisecond), Last: end,
		SPkts: spkts, SBytes: sbytes}
	return flow.Completed{Flow: f, Reason: "idle_timeout", ExportSeq: seq}
}

func TestClassifyExclusionsAndViewpoint(t *testing.T) {
	p := policy()
	cases := []struct {
		init, resp string
		want       Class
	}{
		{"192.0.2.10", "192.0.2.2", Class{AF: "ipv4", Viewpoint: "responder"}},
		{"192.0.2.2", "198.51.100.7", Class{AF: "ipv4", Viewpoint: "initiator"}},
		{"192.0.2.2", "192.0.2.2", Class{AF: "ipv4", Viewpoint: "responder"}},
		{"192.0.2.10", "224.0.0.251", Class{Excluded: "multicast_destination"}},
		{"192.0.2.2", "255.255.255.255", Class{Excluded: "broadcast_destination"}},
		{"192.0.2.2", "192.0.2.255", Class{Excluded: "broadcast_destination"}},
		{"192.0.2.2", "127.0.0.1", Class{Excluded: "loopback_destination"}},
		{"192.0.2.2", "0.0.0.0", Class{Excluded: "unspecified_destination"}},
		{"192.0.2.10", "198.51.100.7", Class{Excluded: "no_local_endpoint"}},
		{"192.0.2.2", "2001:db8::1", Class{Excluded: "invalid_address"}},
	}
	for _, c := range cases {
		if got := p.Classify(netip.MustParseAddr(c.init), netip.MustParseAddr(c.resp)); got != c.want {
			t.Errorf("Classify(%s,%s)=%+v want %+v", c.init, c.resp, got, c.want)
		}
	}
}

func TestWindowReadinessCountsAndFormulas(t *testing.T) {
	b := NewBuilder(policy(), "boot")
	var cs []flow.Completed
	// 前 99 条：60 条来自 peerA 访问 dns，39 条来自 peerB 访问 5000 端口（service "-"）。
	for i := 1; i <= 99; i++ {
		init, port := peerA, uint16(53)
		if i > 60 {
			init, port = peerB, 5000
		}
		cs = append(cs, udp(int64(i), init, host, port, i*10, 2, 100))
	}
	// 第 100 条：peerA → dns，3 包 301 字节，时长 0.5 s。
	cs = append(cs, udp(100, peerA, host, 53, 1000, 3, 301))
	// 一条出站流与一条排除流：出站进窗口，排除只计数。
	cs = append(cs, udp(101, host, remote, 443, 1010, 1, 60), udp(102, peerA, remote, 53, 1020, 1, 60))
	b.Push(cs)
	if b.Pending() != 101 || b.Diag.Excluded["no_local_endpoint"] != 1 {
		t.Fatalf("排除计数错误: pending=%d", b.Pending())
	}
	// 未到重排序延迟时不释放。
	if out := b.Release(t0.Add(30*time.Second), false); len(out) != 0 {
		t.Fatalf("重排序延迟内不应释放: %d", len(out))
	}
	// 截止点 = now − 61 s；最晚一条结束于 t0+1.010 s，因此 now 取 t0+63 s。
	out := b.Release(t0.Add(63*time.Second), false)
	if len(out) != 101 {
		t.Fatalf("应全部释放: %d", len(out))
	}
	for i := 0; i < 99; i++ {
		if out[i].Status != StatusWindowNotReady || out[i].Features != nil {
			t.Fatalf("第 %d 条应为 window_not_ready", i+1)
		}
	}
	r := out[99]
	if r.Status != StatusReady || r.RecordKey != "boot:100" || r.Viewpoint != "responder" || r.AF != "ipv4" {
		t.Fatalf("第 100 条应 ready: %+v", r)
	}
	f := r.Features
	if f.CtSrvSrc != 61 || f.CtSrvDst != 61 || f.CtDstLtm != 100 || f.CtSrcLtm != 61 || f.CtSrcDportLtm != 61 {
		t.Fatalf("窗口计数错误: %+v", f)
	}
	if f.Proto != "udp" || f.Service != "dns" || f.Dur != 0.5 || f.SMean != 100 || f.DMean != 0 {
		t.Fatalf("类别或逐流值错误: %+v", f)
	}
	// sload = 301 × 8 × 2 / 3 / 0.5；dload 反向无包为 0；非 TCP 握手字段为 0。
	if want := float64(301) * 8 * 2 / 3 / 0.5; f.SLoad != want || f.DLoad != 0 || f.TCPRTT != 0 {
		t.Fatalf("load 或握手字段错误: sload=%v want %v", f.SLoad, want)
	}
	// 窗口已满后出站流照常 ready；窗口移除最早一条（peerA 的 #1）。
	o := out[100]
	if o.Status != StatusReady || o.Viewpoint != "initiator" || o.Features.CtSrcLtm != 1 || o.Features.CtDstLtm != 1 {
		t.Fatalf("出站流应 ready 且只计自身: %+v", o.Features)
	}
	if b.Diag.ByStatus[StatusReady] != 2 || b.Diag.ByStatus[StatusWindowNotReady] != 99 {
		t.Fatalf("状态计数错误: %+v", b.Diag.ByStatus)
	}
}

func TestLateAndInvalidRecordsNotEmitted(t *testing.T) {
	b := NewBuilder(policy(), "boot")
	b.Push([]flow.Completed{udp(2, peerA, host, 53, 2000, 1, 60)})
	b.Release(t0.Add(70*time.Second), false)
	// 比已接纳最大键更早结束：迟到拒绝，不入窗。
	b.Push([]flow.Completed{udp(1, peerA, host, 53, 1000, 1, 60)})
	late := b.Release(t0.Add(70*time.Second), true)
	if len(late) != 1 || late[0].Status != StatusLate {
		t.Fatalf("应按迟到拒绝: %+v", late)
	}
	// 续段中 initiator 未发包：spkts=0 占窗口位但拒绝输出。
	b.Push([]flow.Completed{udp(3, peerA, host, 53, 3000, 0, 0)})
	bad := b.Release(t0.Add(70*time.Second), true)
	if bad[0].Status != StatusRejected || bad[0].Reason != "value_invalid" || bad[0].Features != nil {
		t.Fatalf("spkts=0 应拒绝: %+v", bad[0])
	}
}

func TestRoundDivHalfUp(t *testing.T) {
	for _, c := range [][3]int64{{3, 2, 2}, {5, 2, 3}, {7, 3, 2}, {1, 3, 0}, {0, 0, 0}, {100, 2, 50}} {
		if got := roundDiv(c[0], c[1]); got != c[2] {
			t.Errorf("roundDiv(%d,%d)=%d want %d", c[0], c[1], got, c[2])
		}
	}
}
