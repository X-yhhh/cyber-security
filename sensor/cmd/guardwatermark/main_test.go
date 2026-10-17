package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestIdleOnlyPolicySkipsReadTicks(t *testing.T) {
	keep := policies[1].keep
	at := time.Unix(100, 0)
	if keep("frame", at, at) || keep("gap", at, at) {
		t.Fatal("读出帧或缺口后的同刻 tick 必须跳过")
	}
	if !keep("tick", at, at.Add(time.Millisecond)) || !keep("frame", at, at.Add(100*time.Millisecond)) {
		t.Fatal("空闲超时 tick 必须保留")
	}
	if !policies[0].keep("frame", at, at) {
		t.Fatal("原策略保留全部 tick")
	}
}

func TestAttributeExplainsUnknownWithoutRewriting(t *testing.T) {
	start := time.Unix(1000, 0)
	k := tupleKey{netip.MustParseAddrPort("10.0.0.2:55000"), netip.MustParseAddrPort("192.0.2.9:443"), 6}
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	cases := []struct {
		name string
		f    *tupleFacts
		seen time.Time
		want string
	}{
		{"缺事实", nil, at(1), "no_trace_fact"},
		{"关闭后", &tupleFacts{firstTS: at(1), firstSYN: true, synTS: []time.Time{at(1)}, closeTS: []time.Time{at(5)}}, at(20), "after_fin_rst_tombstone"},
		{"SYN 未被接纳", &tupleFacts{firstTS: at(1), firstSYN: true, synTS: []time.Time{at(1)}}, at(1), "pure_syn_seen_not_accepted"},
		{"首见 SYN-ACK", &tupleFacts{firstTS: at(1), firstSYN: true, firstACK: true}, at(1), "first_seen_syn_ack"},
		{"开头已建", &tupleFacts{firstTS: at(3), firstACK: true}, at(3), "midstream_within_first_120s"},
		{"后段中途", &tupleFacts{firstTS: at(600), firstACK: true}, at(600), "midstream_later"},
	}
	for _, c := range cases {
		if got, port := attribute(k, c.f, c.seen, start); got != c.want || port != "local_ephemeral_peer_service" {
			t.Fatalf("%s: got %s/%s", c.name, got, port)
		}
	}
	server := tupleKey{netip.MustParseAddrPort("10.0.0.2:22"), netip.MustParseAddrPort("192.0.2.9:60000"), 6}
	if _, port := attribute(server, nil, start, start); port != "local_service_peer_ephemeral" {
		t.Fatalf("服务端形态: %s", port)
	}
}
