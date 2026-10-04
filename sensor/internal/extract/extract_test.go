package extract

import (
	"bytes"
	"encoding/json"
	"github.com/xyh/cyber-security/sensor/internal/synth"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// 同一抓包开启旁路前后输出逐字节一致；旁路仅有头部统计，特征输出仍无端点。
func TestLabelAuditDoesNotChangeFeatures(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.2")
	peer := netip.MustParseAddr("192.0.2.10")
	var frames []synth.Frame
	t0 := time.Date(2017, 7, 3, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 110; i++ {
		ts := t0.Add(time.Duration(i) * time.Second)
		port := uint16(30000 + i)
		specs := []synth.Spec{
			{TS: ts, Src: peer, Dst: host, SPort: port, DPort: 80, Proto: 6, Flags: synth.SYN},
			{TS: ts.Add(time.Millisecond), Src: host, Dst: peer, SPort: 80, DPort: port, Proto: 6, Flags: synth.SYN | synth.ACK},
			{TS: ts.Add(2 * time.Millisecond), Src: peer, Dst: host, SPort: port, DPort: 80, Proto: 6, Flags: synth.ACK, Payload: 70},
			{TS: ts.Add(3 * time.Millisecond), Src: host, Dst: peer, SPort: 80, DPort: port, Proto: 6, Flags: synth.RST | synth.ACK, Payload: 140},
		}
		for _, s := range specs {
			frames = append(frames, synth.Build(s, 128))
		}
	}
	path := filepath.Join(t.TempDir(), "input.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = synth.WritePcap(f, 128, frames); err != nil {
		t.Fatal(err)
	}
	f.Close()
	opt := Options{LocalAddrs: []netip.Addr{host}, KeyBase: "same", MTU: 1500}
	var plain, withAudit, audit bytes.Buffer
	d1, err := Run(path, &plain, opt)
	if err != nil {
		t.Fatal(err)
	}
	opt.LabelAudit = &audit
	d2, err := Run(path, &withAudit, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain.Bytes(), withAudit.Bytes()) || !reflect.DeepEqual(d1, d2) {
		t.Fatal("旁路改变了特征或诊断")
	}
	if strings.Contains(plain.String(), "192.0.2.") {
		t.Fatal("端点泄漏到特征输出")
	}
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 110 {
		t.Fatal(len(lines))
	}
	for _, raw := range lines {
		var row LabelLine
		if err = json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		if row.Lengths.SPayload != 70 || row.Lengths.DPayload != 140 || row.Lengths.SPackets != 2 || !row.Lengths.Reliable || row.Initiator != peer.String() {
			t.Fatalf("头部长度统计错误: %+v", row.Lengths)
		}
		if row.Lengths.SIPBytes != 150 || row.Lengths.DIPBytes != 220 || !row.Lengths.IPBytesReliable {
			t.Fatalf("原始 IP 字节旁路错误: %+v", row.Lengths)
		}
	}
}
