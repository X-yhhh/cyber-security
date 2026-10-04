// Package packet 解析以太网帧的 IP 与传输层头部（特征规格 §1.3、D8）。
//
// 只读取 IP/TCP/UDP 头部字段，不保留、不返回任何载荷字节。输入受 snaplen（128 字节）限制，
// 线路长度另行传入，用于 IP 长度字段为 0（巨型帧或卸载）时推算总长。
package packet

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Status 是单帧解析结论；非 OK 的帧只计入 diagnostics。
type Status int

const (
	OK Status = iota
	NonIP
	Truncated
	Malformed
)

var statusNames = map[Status]string{OK: "ok", NonIP: "non_ip", Truncated: "truncated", Malformed: "malformed"}

func (s Status) String() string { return statusNames[s] }

// Packet 是单个报文的头部元数据。
type Packet struct {
	TS           time.Time
	AF           uint8 // 4 或 6
	Src, Dst     netip.Addr
	SPort, DPort uint16 // ICMP 等无端口协议为 0
	Proto        uint8
	IPTotal      int // IP 数据报总长（含 IP 头，不含链路层头）
	IPHdr        int // IP 头长；IPv6 含扩展头
	TCPHdr       int
	SYN, ACK     bool
	FIN, RST     bool
	MSS          uint16 // SYN 携带的 MSS 选项；0 表示未携带或被截断
	L2Broadcast  bool
	VLAN         bool
	IPOptions    bool
	TotalFromCap bool // 长度字段为 0，改用线路长度推算
	FirstFrag    bool
	LaterFrag    bool // 非首片：没有传输层头
	FragID       uint32
	TCPOptTrunc  bool // TCP 选项被 snaplen 截断（端口与标志位仍可用）
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

// ParseEthernet 解析以太网帧。data 为捕获字节，wireLen 为线路帧长。
func ParseEthernet(data []byte, wireLen int, ts time.Time) (Packet, Status) {
	p := Packet{TS: ts}
	if len(data) < 14 {
		return p, Truncated
	}
	p.L2Broadcast = data[0]&data[1]&data[2]&data[3]&data[4]&data[5] == 0xff
	etype := be16(data[12:14])
	off := 14
	for etype == 0x8100 || etype == 0x88a8 {
		if len(data) < off+4 {
			return p, Truncated
		}
		p.VLAN = true
		etype = be16(data[off+2 : off+4])
		off += 4
	}
	return parseIP(p, data[off:], etype, wireLen-off)
}

// parseIP 解析 IP 层及其后的传输层头部；l3Wire 为线路上的 IP 层长度（线路帧长 − 链路层头）。
func parseIP(p Packet, b []byte, etype uint16, l3Wire int) (Packet, Status) {
	switch etype {
	case 0x0800:
		if len(b) < 20 {
			return p, Truncated
		}
		ihl := int(b[0]&0x0f) * 4
		if b[0]>>4 != 4 || ihl < 20 {
			return p, Malformed
		}
		if len(b) < ihl {
			return p, Truncated
		}
		p.AF, p.IPHdr, p.IPOptions = 4, ihl, ihl > 20
		p.IPTotal = int(be16(b[2:4]))
		ff := be16(b[6:8])
		p.Proto = b[9]
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.FragID = uint32(be16(b[4:6]))
		if ff&0x1fff != 0 {
			p.LaterFrag = true
		} else if ff&0x2000 != 0 {
			p.FirstFrag = true
		}
	case 0x86dd:
		if len(b) < 40 {
			return p, Truncated
		}
		if b[0]>>4 != 6 {
			return p, Malformed
		}
		p.AF = 6
		if pl := int(be16(b[4:6])); pl != 0 {
			p.IPTotal = 40 + pl
		}
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		next, hdr := b[6], 40
	ext:
		for i := 0; i < 8; i++ {
			switch next {
			case 0, 43, 60: // 逐跳、路由、目的选项
				if len(b) < hdr+2 {
					return p, Truncated
				}
				next, hdr = b[hdr], hdr+(int(b[hdr+1])+1)*8
			case 51: // AH
				if len(b) < hdr+2 {
					return p, Truncated
				}
				next, hdr = b[hdr], hdr+(int(b[hdr+1])+2)*4
			case 44: // 分片
				if len(b) < hdr+8 {
					return p, Truncated
				}
				p.FragID = binary.BigEndian.Uint32(b[hdr+4 : hdr+8])
				if be16(b[hdr+2:hdr+4])>>3 != 0 {
					p.LaterFrag = true
				} else if b[hdr+3]&1 != 0 {
					p.FirstFrag = true
				}
				next, hdr = b[hdr], hdr+8
			default:
				break ext
			}
		}
		p.IPHdr, p.Proto = hdr, next
	default:
		return p, NonIP
	}
	// §1.3：长度字段为 0（或小于头长）时取「线路长度 − 链路层头长」。
	if p.IPTotal < p.IPHdr {
		p.IPTotal = l3Wire
		p.TotalFromCap = true
	}
	if p.LaterFrag {
		return p, OK
	}
	if len(b) < p.IPHdr {
		return p, Truncated
	}
	t := b[p.IPHdr:]
	switch p.Proto {
	case 6:
		if len(t) < 14 {
			return p, Truncated
		}
		p.SPort, p.DPort = be16(t[0:2]), be16(t[2:4])
		p.TCPHdr = int(t[12]>>4) * 4
		if p.TCPHdr < 20 {
			return p, Malformed
		}
		fl := t[13]
		p.FIN, p.SYN, p.RST, p.ACK = fl&0x01 != 0, fl&0x02 != 0, fl&0x04 != 0, fl&0x10 != 0
		if len(t) < p.TCPHdr {
			p.TCPOptTrunc = true
		} else if p.SYN {
			p.MSS = findMSS(t[20:p.TCPHdr])
		}
	case 17:
		if len(t) < 4 {
			return p, Truncated
		}
		p.SPort, p.DPort = be16(t[0:2]), be16(t[2:4])
	}
	return p, OK
}

// findMSS 在 TCP 选项中查找 MSS（kind=2, len=4）。只读头部选项。
func findMSS(o []byte) uint16 {
	for i := 0; i < len(o); {
		switch o[i] {
		case 0:
			return 0
		case 1:
			i++
			continue
		}
		if i+1 >= len(o) || o[i+1] < 2 {
			return 0
		}
		if o[i] == 2 && o[i+1] == 4 && i+4 <= len(o) {
			return be16(o[i+2 : i+4])
		}
		i += int(o[i+1])
	}
	return 0
}
