package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestClassifyByInitialSyn(t *testing.T) {
	states := map[tupleKey]*tupleState{}
	k := tupleKey{netip.MustParseAddrPort("10.0.0.2:21"), netip.MustParseAddrPort("192.0.2.9:50000")}
	if c, start := classify(states, k, false, true, 7); c != classPeer || !start {
		t.Fatalf("对端起始 SYN: %s %v", c, start)
	}
	if c, start := classify(states, k, true, false, 0); c != classPeer || start {
		t.Fatalf("同连接后续包: %s %v", c, start)
	}
	if c, start := classify(states, k, false, true, 7); c != classPeer || start {
		t.Fatalf("重传同序号 SYN 不是新连接: %s %v", c, start)
	}
	if c, start := classify(states, k, false, true, 9); c != classPeer || !start {
		t.Fatalf("新序号 SYN 是新连接: %s %v", c, start)
	}
	m := tupleKey{netip.MustParseAddrPort("10.0.0.2:55000"), netip.MustParseAddrPort("192.0.2.9:443")}
	if c, start := classify(states, m, true, false, 0); c != classPreexisting || !start {
		t.Fatalf("无 SYN 首包: %s %v", c, start)
	}
	if c, start := classify(states, m, true, true, 3); c != classLocal || !start {
		t.Fatalf("已建连接后见到本机 SYN: %s %v", c, start)
	}
}

// 合成场景：攻击方在 30 秒内发起 6 个连接（对端发起），本机同时向同一对端发起 10 个 HTTPS 连接。
// 冻结口径两者混算；候选 C1 只计对端发起，攻击仍越过 brute-starts 阈值。
func TestWindowSplitsInitiatorForCandidate(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	var list []peerEvent
	for i := 0; i < 10; i++ {
		list = append(list, peerEvent{at: base.Add(time.Duration(i) * time.Second), class: classLocal, start: true, port: 443, inBytes: 5000})
	}
	for i := 0; i < 6; i++ {
		list = append(list, peerEvent{at: base.Add(time.Duration(10+i) * time.Second), class: classPeer, start: true, port: 21, inBytes: 100})
	}
	starts, inBytes, ports := window(list, base.Add(20*time.Second), 30)
	if starts[classLocal] != 10 || starts[classPeer] != 6 || ports[443] != 10 || ports[21] != 6 {
		t.Fatalf("starts=%v ports=%v", starts, ports)
	}
	if inBytes[classLocal] != 50000 || inBytes[classPeer] != 600 {
		t.Fatalf("inBytes=%v", inBytes)
	}
	if float64(starts[classPeer]) < rules[1].Threshold {
		t.Fatal("对端发起的 6 个连接应保留 brute-starts 命中")
	}
	// 窗口左开右闭：恰在 asOf-30s 的事件不计入。
	if s, _, _ := window(list, base.Add(30*time.Second), 30); s[classLocal] != 9 {
		t.Fatalf("左边界: %v", s)
	}
}
