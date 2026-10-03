package hostguard

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xyh/cyber-security/sensor/internal/synth"
)

func TestRawIPParityAndUnknownLinkRejected(t *testing.T) {
	f := synth.Build(synth.Spec{TS: epoch, Src: peer, Dst: host, SPort: 40000, DPort: 80, Proto: 6, Flags: synth.SYN, Payload: 30}, 256)
	var expected []Observation
	e, _ := New(config(&expected))
	if err := e.Frame(f.Data, f.WireLen, f.TS, 1); err != nil {
		t.Fatal(err)
	}
	closeEngine(t, e)
	for _, link := range []uint32{12, 101, 999} {
		path := filepath.Join(t.TempDir(), "raw.pcap")
		h := make([]byte, 40)
		binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
		binary.LittleEndian.PutUint16(h[4:], 2)
		binary.LittleEndian.PutUint16(h[6:], 4)
		binary.LittleEndian.PutUint32(h[16:], 256)
		binary.LittleEndian.PutUint32(h[20:], link)
		binary.LittleEndian.PutUint32(h[24:], uint32(epoch.Unix()))
		binary.LittleEndian.PutUint32(h[32:], uint32(len(f.Data)-14))
		binary.LittleEndian.PutUint32(h[36:], uint32(f.WireLen-14))
		if err := os.WriteFile(path, append(h, f.Data[14:]...), 0600); err != nil {
			t.Fatal(err)
		}
		var got []Observation
		e, _ = New(config(&got))
		err := ReadPCAP(path, e)
		if link == 999 {
			if err == nil {
				t.Fatal("未知链路未拒绝")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatal("RAW/Ethernet 特征不一致")
		}
	}
}
func TestTruncatedContainerFailsWithoutSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0600); err != nil {
		t.Fatal(err)
	}
	var rows []Observation
	e, _ := New(config(&rows))
	if err := ReadPCAP(path, e); err == nil {
		t.Fatal("损坏容器未拒绝")
	}
}
func TestMissingVectorAndCapacityBudgets(t *testing.T) {
	var rows []Observation
	c := config(&rows)
	c.MaxBufferedPackets = 1
	e, _ := New(c)
	p := pkt(0, false, false, false, 1)
	p.Proto = 17
	push(t, e, p)
	p = pkt(50, false, false, false, 2)
	p.Proto = 17
	push(t, e, p)
	closeEngine(t, e)
	if len(rows) != 1 || !rows[0].Quality.CapacityDrop || e.Stats["buffer_drops"] != 1 {
		t.Fatal("缓冲容量未有界拒绝")
	}
	v, err := ModelVector(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := 9; i <= 15; i++ {
		if v.Missing[i] != 1 || v.Values[i] != 0 {
			t.Fatal("结构性缺失 mask 错误")
		}
	}
	if v.Missing[1] != 0 || v.Values[1] != 0 {
		t.Fatal("实测零值被当缺失")
	}
	rows = nil
	c = config(&rows)
	c.MaxContextEvents = 1
	e, _ = New(c)
	push(t, e, pkt(0, false, true, false, 1))
	push(t, e, pkt(500, false, false, true, 2))
	tick(t, e, 1100)
	if !rows[0].Quality.CapacityDrop || rows[0].Contexts[2].CoverageMs != 500 {
		t.Fatal("上下文容量未重置")
	}
	rows = nil
	c = config(&rows)
	c.MaxConnections = 1
	e, _ = New(c)
	push(t, e, pkt(0, false, true, false, 1))
	p = pkt(500, false, true, false, 2)
	p.SPort++
	push(t, e, p)
	tick(t, e, 1100)
	if e.Stats["connection_drops"] != 1 || !rows[0].Quality.CapacityDrop {
		t.Fatal("连接身份表超限未拒绝")
	}
}
