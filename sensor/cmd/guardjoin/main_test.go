package main

import (
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/packet"
	"testing"
	"time"
)

func TestOnsetRequiresContinuousIncompleteRequest(t *testing.T) {
	makeLabel := func() *label {
		l := &label{Label: "DoS Slowloris"}
		l.review(hostguard.Packet{Packet: packet.Packet{SYN: true}, Seq: 100}, nil)
		return l
	}
	add := func(l *label, seq uint32, text string, at int64) {
		p := hostguard.Packet{Packet: packet.Packet{TS: time.UnixMicro(at), IPHdr: 20, TCPHdr: 20}, Seq: seq, PayloadBytes: len(text)}
		l.review(p, append(make([]byte, 54), []byte(text)...))
	}
	request := "GET / HTTP/1.1\r\nHost: example.invalid\r\n"
	l := makeLabel()
	add(l, 101, request, 1000)
	if l.onset != nil {
		t.Fatal("GET 不能单独证明起点")
	}
	seq := uint32(101 + len(request))
	add(l, seq, "X-a: b\r\n", 2000)
	if l.onset == nil || *l.onset != 2000 {
		t.Fatal("未识别连续头片段")
	}
	add(l, seq, "X-a: b\r\n", 3000)
	if l.continuations != 1 {
		t.Fatal("重传增加了证据")
	}
	gap := makeLabel()
	add(gap, 102, request, 1000)
	if gap.reviewError != "sequence_gap" || gap.onset != nil {
		t.Fatal("序号缺口仍授予起点")
	}
	complete := makeLabel()
	add(complete, 101, request+"\r\n", 1000)
	add(complete, uint32(103+len(request)), "X-a: b\r\n", 2000)
	if complete.onset != nil {
		t.Fatal("正常完整请求误标")
	}
	missing := &label{Label: "DoS Slowloris"}
	add(missing, 101, request, 1000)
	if missing.reviewError != "missing_syn" {
		t.Fatal("缺失 SYN 未拒绝")
	}
}
