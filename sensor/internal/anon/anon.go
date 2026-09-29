// Package anon 把本机抓取的 pcap 假名化，供 G2 真实流量 fixtures 入库（路线 B §12.3 第 4 步）。
//
// 规则（只做保持分类关系的改写，特征值不变）：
//   - 本机 IPv4 子网（须为 /24）内的地址映射到 192.0.2.0/24，保留末字节：本机、网关、定向广播的关系不变；
//   - 其他 IPv4 单播按首次出现顺序映射到 198.18.0.0/15；IPv4 多播、受限广播、回环、未指定地址不变；
//   - 本机 IPv6 地址依次映射到 2001:db8::2、::3…；其他 IPv6 单播映射到 2001:db8:1::N，链路本地到 fe80::N；
//     被请求节点多播（含地址低 24 位）映射到 ff02::1:ff00:N，其余 IPv6 多播不变；
//   - MAC：广播不变，组播统一为 01:00:00:00:00:00，单播按顺序映射到 02:00:00:00:NN:NN；
//   - 每帧只保留到传输层头部（TCP 含选项；UDP/ICMP/ICMPv6 8 字节；后续分片只保留 IP 头），载荷不保留；
//     IPv4 选项内容、传输层校验和清零，IPv4 头校验和重算；非 IP 或解析失败的帧只保留以太网头；
//   - 时间整体平移到 Start（保留微秒），线路长度不变。
//
// 映射表只在内存中，不落盘、不打印。映射是单射，因此地址相等关系（ct_* 计数）不变。
package anon

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/packet"
)

// Options 是假名化参数。
type Options struct {
	Subnet  netip.Prefix // 本机 IPv4 子网，须为 /24
	LocalV6 []netip.Addr // 本机 IPv6 地址（映射后仍是本机地址）
	Start   time.Time    // 输出首帧的整秒时间
}

// Anonymizer 不是线程安全的。
type Anonymizer struct {
	opt   Options
	addrs map[netip.Addr]netip.Addr
	macs  map[[6]byte][6]byte
	next  map[string]uint32
	shift time.Duration
	begun bool
}

var (
	docV4     = netip.MustParsePrefix("192.0.2.0/24")
	benchV4   = netip.MustParseAddr("198.18.0.0")
	solicited = netip.MustParsePrefix("ff02::1:ff00:0/104")
	bcast     = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// New 校验参数并预置本机地址映射。
func New(opt Options) (*Anonymizer, error) {
	if !opt.Subnet.Addr().Is4() || opt.Subnet.Bits() != 24 || opt.Start.IsZero() {
		return nil, errors.New("须提供 /24 的本机 IPv4 子网与输出起点")
	}
	a := &Anonymizer{opt: opt, addrs: map[netip.Addr]netip.Addr{}, macs: map[[6]byte][6]byte{}, next: map[string]uint32{}}
	for i, l := range opt.LocalV6 {
		if !l.Is6() || l.Is4In6() {
			return nil, errors.New("本机 IPv6 地址无效")
		}
		a.addrs[l] = v6(0x20010db8, 0, uint32(2+i))
	}
	return a, nil
}

func v6(hi, mid, lo uint32) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint32(b[0:], hi)
	binary.BigEndian.PutUint32(b[4:], mid)
	binary.BigEndian.PutUint32(b[12:], lo)
	return netip.AddrFrom16(b)
}

func (a *Anonymizer) seq(class string) uint32 { a.next[class]++; return a.next[class] }

// Map 返回地址的假名；同一输入恒得同一输出。
func (a *Anonymizer) Map(x netip.Addr) netip.Addr {
	if m, ok := a.addrs[x]; ok {
		return m
	}
	var m netip.Addr
	switch {
	case x.IsLoopback() || x.IsUnspecified() || x == bcast || (x.IsMulticast() && !solicited.Contains(x)):
		return x
	case x.Is4() && a.opt.Subnet.Contains(x):
		b := docV4.Addr().As4()
		b[3] = x.As4()[3]
		m = netip.AddrFrom4(b)
	case x.Is4():
		b := benchV4.As4()
		v := binary.BigEndian.Uint32(b[:]) + a.seq("v4")
		binary.BigEndian.PutUint32(b[:], v)
		m = netip.AddrFrom4(b)
	case solicited.Contains(x):
		m = v6(0xff020000, 0, 0x01ff0000+a.seq("sol"))
	case x.IsLinkLocalUnicast():
		m = v6(0xfe800000, 0, a.seq("ll"))
	default:
		m = v6(0x20010db8, 0x00010000, a.seq("v6"))
	}
	a.addrs[x] = m
	return m
}

func (a *Anonymizer) mac(b []byte) {
	var k [6]byte
	copy(k[:], b)
	switch {
	case k == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}:
		return
	case k[0]&1 == 1:
		copy(b, []byte{0x01, 0, 0, 0, 0, 0})
		return
	}
	v, ok := a.macs[k]
	if !ok {
		n := len(a.macs) + 1
		v = [6]byte{0x02, 0, 0, 0, byte(n >> 8), byte(n)}
		a.macs[k] = v
	}
	copy(b, v[:])
}

// Rewrite 返回假名化后的帧数据与时间戳；wireLen 不变。
func (a *Anonymizer) Rewrite(data []byte, wireLen int, ts time.Time) ([]byte, time.Time) {
	if !a.begun {
		a.shift, a.begun = a.opt.Start.Sub(ts.Truncate(time.Second)), true
	}
	ts = ts.Add(a.shift)
	if len(data) < 14 {
		return make([]byte, len(data)), ts
	}
	p, st := packet.ParseEthernet(data, wireLen, ts)
	off := 14
	for etype := binary.BigEndian.Uint16(data[12:14]); (etype == 0x8100 || etype == 0x88a8) && len(data) >= off+4; off += 4 {
		etype = binary.BigEndian.Uint16(data[off+2 : off+4])
	}
	if st != packet.OK {
		out := append([]byte(nil), data[:14]...)
		a.mac(out[0:6])
		a.mac(out[6:12])
		return out, ts
	}
	keep := p.IPHdr
	if !p.LaterFrag {
		switch p.Proto {
		case 6:
			keep += p.TCPHdr
		case 17, 1, 58:
			keep += 8
		}
	}
	end := min(off+keep, len(data))
	out := append([]byte(nil), data[:end]...)
	a.mac(out[0:6])
	a.mac(out[6:12])
	l3 := out[off:]
	src, dst := a.Map(p.Src), a.Map(p.Dst)
	if p.AF == 4 {
		s, d := src.As4(), dst.As4()
		copy(l3[12:16], s[:])
		copy(l3[16:20], d[:])
		clear(l3[20:p.IPHdr])
		clear(l3[10:12])
		binary.BigEndian.PutUint16(l3[10:12], checksum(l3[:p.IPHdr]))
	} else {
		s, d := src.As16(), dst.As16()
		copy(l3[8:24], s[:])
		copy(l3[24:40], d[:])
	}
	if t := l3[min(p.IPHdr, len(l3)):]; !p.LaterFrag {
		switch {
		case p.Proto == 6 && len(t) >= 18:
			clear(t[16:18])
		case p.Proto == 17 && len(t) >= 8:
			clear(t[6:8])
		case (p.Proto == 1 || p.Proto == 58) && len(t) >= 4:
			clear(t[2:4])
		}
	}
	return out, ts
}

func checksum(h []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(h); i += 2 {
		s += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
