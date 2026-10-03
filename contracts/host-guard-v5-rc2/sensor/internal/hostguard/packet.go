package hostguard

import (
	"encoding/binary"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
)

// Packet 只包含可观察头部；TCP 序号用于 epoch/握手核验，不输出为模型字段。
type Packet struct {
	packet.Packet
	CaptureSeq   uint64
	Seq, Ack     uint32
	PayloadBytes int
	Quality      Quality
}

// Parse 复用 v4 的链路/IP解析，额外拒绝 v4 的长度猜测、部分传输头和分片。
// snaplen 省略载荷不算截断；IP 长度超过线路长度、必要头不完整则不得造流。
func Parse(data []byte, wire int, ts time.Time, seq uint64, mtu int) (Packet, string) {
	p, st := packet.ParseEthernet(data, wire, ts.UTC().Truncate(time.Microsecond))
	r := Packet{Packet: p, CaptureSeq: seq}
	if st == packet.NonIP {
		return r, "non_ip"
	}
	if st != packet.OK {
		r.Quality.Truncated = true
		return r, "invalid_header"
	}
	if p.FirstFrag || p.LaterFrag {
		r.Quality.CaptureGap = true
		return r, "fragment"
	}
	if p.AF == 6 && (p.Proto == 0 || p.Proto == 43 || p.Proto == 44 || p.Proto == 51 || p.Proto == 60) {
		r.Quality.CaptureGap = true
		return r, "unsupported_extension_chain"
	}
	off := 14
	for off <= len(data) && (binary.BigEndian.Uint16(data[off-2:off]) == 0x8100 || binary.BigEndian.Uint16(data[off-2:off]) == 0x88a8) {
		off += 4
	}
	if p.TotalFromCap || p.TCPOptTrunc || p.IPTotal > wire-off || p.IPTotal < p.IPHdr {
		r.Quality.Truncated = true
		return r, "invalid_length"
	}
	start := off + p.IPHdr
	need := 0
	switch p.Proto {
	case 6:
		need = p.TCPHdr
	case 17:
		need = 8
	case 1, 58:
		need = 8
	}
	if start+need > len(data) || p.IPTotal < p.IPHdr+need {
		r.Quality.Truncated = true
		return r, "invalid_header"
	}
	if p.Proto == 6 {
		r.Seq = binary.BigEndian.Uint32(data[start+4 : start+8])
		r.Ack = binary.BigEndian.Uint32(data[start+8 : start+12])
		r.PayloadBytes = p.IPTotal - p.IPHdr - p.TCPHdr
	}
	if p.Proto == 17 {
		length := int(binary.BigEndian.Uint16(data[start+4 : start+6]))
		if length < 8 || length != p.IPTotal-p.IPHdr {
			r.Quality.Truncated = true
			return r, "invalid_udp_length"
		}
	}
	r.Quality.OffloadSuspected = p.IPTotal > mtu
	return r, "ok"
}
