// Package synth 构造确定性的合成以太网帧与经典 pcap 文件，只用于测试与 G2 包级 fixtures。
//
// 帧内容全部由参数决定（文档保留地址 RFC 5737 / RFC 3849），载荷为零字节填充，不含任何真实流量。
// 本包不打开网卡、不发送报文。
package synth

import (
	"encoding/binary"
	"io"
	"net/netip"
	"time"
)

// TCP 标志位。
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Frame 是一帧及其时间戳与线路长度。
type Frame struct {
	TS      time.Time
	Data    []byte
	WireLen int
}

// Spec 描述一个报文。Payload 为 IP 层之上（传输层头之后）的载荷字节数，载荷全为 0。
type Spec struct {
	TS           time.Time
	Src, Dst     netip.Addr
	SPort, DPort uint16
	Proto        uint8 // 6 TCP、17 UDP、1 ICMP、58 ICMPv6，其他协议只写 IP 头
	Flags        uint8 // TCP 标志
	MSS          uint16
	Payload      int
	// 分片：FragOffset 以 8 字节为单位；MoreFrags 置 MF。非首片不写传输层头。
	FragID     uint32
	FragOffset uint16
	MoreFrags  bool
	// ZeroLength 把 IP 长度字段写为 0（模拟卸载），总长由线路长度推算。
	ZeroLength bool
	VLAN       bool
}

var srcMAC = []byte{0x02, 0, 0, 0, 0, 0x01}
var dstMAC = []byte{0x02, 0, 0, 0, 0, 0x02}

// Build 构造一帧。Data 截断到 snaplen（0 表示不截断），WireLen 为完整帧长。
func Build(s Spec, snaplen int) Frame {
	var l4 []byte
	later := s.FragOffset != 0
	if !later {
		switch s.Proto {
		case 6:
			hlen := 20
			if s.MSS != 0 {
				hlen = 24
			}
			l4 = make([]byte, hlen)
			binary.BigEndian.PutUint16(l4[0:], s.SPort)
			binary.BigEndian.PutUint16(l4[2:], s.DPort)
			l4[12] = byte(hlen/4) << 4
			l4[13] = s.Flags
			binary.BigEndian.PutUint16(l4[14:], 65535)
			if s.MSS != 0 {
				l4[20], l4[21] = 2, 4
				binary.BigEndian.PutUint16(l4[22:], s.MSS)
			}
		case 17:
			l4 = make([]byte, 8)
			binary.BigEndian.PutUint16(l4[0:], s.SPort)
			binary.BigEndian.PutUint16(l4[2:], s.DPort)
			binary.BigEndian.PutUint16(l4[4:], uint16(8+s.Payload))
		case 1, 58:
			l4 = make([]byte, 8)
			l4[0] = 8
			if s.Proto == 58 {
				l4[0] = 128
			}
		}
	}
	l4 = append(l4, make([]byte, s.Payload)...)

	var ip []byte
	if s.Src.Is4() {
		ip = make([]byte, 20)
		ip[0] = 0x45
		if !s.ZeroLength {
			binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		}
		binary.BigEndian.PutUint16(ip[4:], uint16(s.FragID))
		ff := s.FragOffset & 0x1fff
		if s.MoreFrags {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], ff)
		ip[8] = 64
		ip[9] = s.Proto
		a, b := s.Src.As4(), s.Dst.As4()
		copy(ip[12:], a[:])
		copy(ip[16:], b[:])
	} else {
		ip = make([]byte, 40)
		ip[0] = 0x60
		next := s.Proto
		var ext []byte
		if s.FragOffset != 0 || s.MoreFrags {
			ext = make([]byte, 8)
			ext[0] = s.Proto
			fo := s.FragOffset << 3
			if s.MoreFrags {
				fo |= 1
			}
			binary.BigEndian.PutUint16(ext[2:], fo)
			binary.BigEndian.PutUint32(ext[4:], s.FragID)
			next = 44
		}
		if !s.ZeroLength {
			binary.BigEndian.PutUint16(ip[4:], uint16(len(ext)+len(l4)))
		}
		ip[6], ip[7] = next, 64
		a, b := s.Src.As16(), s.Dst.As16()
		copy(ip[8:], a[:])
		copy(ip[24:], b[:])
		ip = append(ip, ext...)
	}

	eth := append([]byte{}, dstMAC...)
	eth = append(eth, srcMAC...)
	etype := []byte{0x08, 0x00}
	if s.Src.Is6() {
		etype = []byte{0x86, 0xdd}
	}
	if s.VLAN {
		eth = append(eth, 0x81, 0x00, 0x00, 0x0a)
	}
	eth = append(eth, etype...)
	frame := append(append(eth, ip...), l4...)
	data := frame
	if snaplen > 0 && len(data) > snaplen {
		data = data[:snaplen]
	}
	return Frame{TS: s.TS, Data: append([]byte{}, data...), WireLen: len(frame)}
}

// WritePcap 写经典 pcap（微秒时间戳、LINKTYPE_ETHERNET）。
func WritePcap(w io.Writer, snaplen int, frames []Frame) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], uint32(snaplen))
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	for _, f := range frames {
		rec := make([]byte, 16)
		us := f.TS.UnixMicro()
		binary.LittleEndian.PutUint32(rec[0:], uint32(us/1_000_000))
		binary.LittleEndian.PutUint32(rec[4:], uint32(us%1_000_000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f.Data)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(f.WireLen))
		if _, err := w.Write(rec); err != nil {
			return err
		}
		if _, err := w.Write(f.Data); err != nil {
			return err
		}
	}
	return nil
}
