package synth

import (
	"net/netip"
	"sort"
	"time"
)

// G2 包级 fixtures 的合成场景（路线 B 阶段 6，G2 跨语言对拍）。
//
// 全部使用文档保留地址（RFC 5737 / RFC 3849），载荷为零字节，时间戳为固定起点加确定偏移，
// 生成结果逐字节可复现。场景编号与 fixture.json 的 coverage 对应。
var (
	G2Start  = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	G2Host   = netip.MustParseAddr("192.0.2.2")
	G2HostV6 = netip.MustParseAddr("2001:db8::2")
	G2Subnet = netip.MustParsePrefix("192.0.2.0/24")
)

// G2SnapLen 与传感器实时抓包一致。
const G2SnapLen = 128

// G2Coverage 列出场景覆盖的边界，写入 fixture.json。
var G2Coverage = []string{
	"window_fill_ipv4", "tcp_full_handshake_fin", "tcp_rst", "tombstone_absorb_then_pure_syn",
	"midstream_no_handshake", "max_lifetime_split_continuation", "d11_oversize_mss_split",
	"ipv4_fragments_and_orphan", "icmp_no_ports", "vlan_dhcp", "ip_length_zero_uses_wire_length",
	"exclude_multicast", "exclude_limited_broadcast", "exclude_directed_broadcast", "exclude_no_local_endpoint",
	"outbound_initiator_viewpoint", "ipv6_window_and_handshake", "proto_out_of_table", "non_ip_frame",
}

// G2Frames 返回按时间排序的全部帧。
func G2Frames() []Frame {
	var fs []Frame
	at := func(ms int) time.Time { return G2Start.Add(time.Duration(ms) * time.Millisecond) }
	add := func(s Spec) { fs = append(fs, Build(s, G2SnapLen)) }
	v4 := func(last byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, last}) }
	ext := func(last byte) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, last}) }
	tcp := func(ms int, src, dst netip.Addr, sp, dp uint16, flags uint8, payload int, mss uint16) {
		add(Spec{TS: at(ms), Src: src, Dst: dst, SPort: sp, DPort: dp, Proto: 6, Flags: flags, Payload: payload, MSS: mss})
	}
	handshake := func(ms int, c, s netip.Addr, cp, sp uint16) {
		tcp(ms, c, s, cp, sp, SYN, 0, 1460)
		tcp(ms+20, s, c, sp, cp, SYN|ACK, 0, 1400)
		tcp(ms+45, c, s, cp, sp, ACK, 0, 0)
	}

	// window_fill_ipv4：150 对 DNS 请求/应答，5 个对端轮换。
	for i := 0; i < 150; i++ {
		peer := v4(byte(10 + i%5))
		add(Spec{TS: at(i * 200), Src: peer, Dst: G2Host, SPort: uint16(30000 + i), DPort: 53, Proto: 17, Payload: 40})
		add(Spec{TS: at(i*200 + 1), Src: G2Host, Dst: peer, SPort: 53, DPort: uint16(30000 + i), Proto: 17, Payload: 90 + i%7})
	}
	// tcp_full_handshake_fin；tombstone_absorb_then_pure_syn：墓碑期内尾随 ACK 被吸收，纯 SYN 开新流。
	c := v4(20)
	handshake(40_000, c, G2Host, 41000, 80)
	tcp(40_060, c, G2Host, 41000, 80, ACK|PSH, 120, 0)
	tcp(40_090, G2Host, c, 80, 41000, ACK|PSH, 900, 0)
	tcp(40_100, c, G2Host, 41000, 80, FIN|ACK, 0, 0)
	tcp(40_120, G2Host, c, 80, 41000, FIN|ACK, 0, 0)
	tcp(41_000, c, G2Host, 41000, 80, ACK, 0, 0)
	tcp(42_000, c, G2Host, 41000, 80, SYN, 0, 1460)
	// tcp_rst
	tcp(41_500, v4(21), G2Host, 41001, 22, SYN, 0, 1460)
	tcp(41_510, G2Host, v4(21), 22, 41001, RST|ACK, 0, 0)
	// midstream_no_handshake：首包来自本机，本机为 initiator。
	tcp(45_000, G2Host, v4(22), 443, 42000, ACK|PSH, 300, 0)
	tcp(45_010, v4(22), G2Host, 42000, 443, ACK, 0, 0)
	// max_lifetime_split_continuation：握手后只有 responder 发包，60 s 处切段，续段 spkts=0 被拒。
	handshake(50_000, v4(23), G2Host, 43000, 8080)
	for ms := 51_000; ms <= 125_000; ms += 1_000 {
		tcp(ms, G2Host, v4(23), 8080, 43000, ACK|PSH, 200, 0)
	}
	// d11_oversize_mss_split：4000 字节 GSO 大包按 responder 通告的 MSS 1400 折算。
	handshake(130_000, v4(24), G2Host, 44000, 21)
	tcp(130_100, v4(24), G2Host, 44000, 21, ACK|PSH, 4000, 0)
	// ipv4_fragments_and_orphan
	add(Spec{TS: at(132_000), Src: v4(25), Dst: G2Host, SPort: 5000, DPort: 161, Proto: 17, Payload: 1472, FragID: 7, MoreFrags: true})
	add(Spec{TS: at(132_001), Src: v4(25), Dst: G2Host, Proto: 17, Payload: 500, FragID: 7, FragOffset: 185})
	add(Spec{TS: at(132_002), Src: v4(25), Dst: G2Host, Proto: 17, Payload: 100, FragID: 9, FragOffset: 10})
	// icmp_no_ports
	add(Spec{TS: at(134_000), Src: v4(26), Dst: G2Host, Proto: 1, Payload: 56})
	add(Spec{TS: at(134_001), Src: G2Host, Dst: v4(26), Proto: 1, Payload: 56})
	// vlan_dhcp；ip_length_zero_uses_wire_length
	add(Spec{TS: at(135_000), Src: v4(27), Dst: G2Host, SPort: 68, DPort: 67, Proto: 17, Payload: 300, VLAN: true})
	add(Spec{TS: at(135_500), Src: v4(29), Dst: G2Host, SPort: 45000, DPort: 25, Proto: 6, Flags: ACK, Payload: 600, ZeroLength: true})
	// exclude_*：多播、受限广播、定向广播、两端都不是本机。
	add(Spec{TS: at(136_000), Src: v4(10), Dst: netip.MustParseAddr("224.0.0.251"), SPort: 5353, DPort: 5353, Proto: 17, Payload: 30})
	add(Spec{TS: at(136_100), Src: G2Host, Dst: netip.MustParseAddr("255.255.255.255"), SPort: 68, DPort: 67, Proto: 17, Payload: 300})
	add(Spec{TS: at(136_200), Src: G2Host, Dst: v4(255), SPort: 137, DPort: 137, Proto: 17, Payload: 50})
	add(Spec{TS: at(136_300), Src: ext(7), Dst: ext(8), SPort: 46000, DPort: 80, Proto: 6, Flags: SYN, MSS: 1460})
	// outbound_initiator_viewpoint
	handshake(137_000, G2Host, ext(9), 50000, 443)
	// proto_out_of_table：协议号 253 记 proto-253（词表外，后端按漂移信号处理）。
	add(Spec{TS: at(138_000), Src: v4(28), Dst: G2Host, Proto: 253, Payload: 20})
	// non_ip_frame：ARP 只计入解析诊断。
	arp := make([]byte, 42)
	copy(arp, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x06})
	fs = append(fs, Frame{TS: at(139_000), Data: arp, WireLen: 42})
	// ipv6_window_and_handshake：100 条 IPv6 UDP 填满 IPv6 窗口后再做一次握手。
	for i := 0; i < 100; i++ {
		peer := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(0x10 + i%3)})
		add(Spec{TS: at(150_000 + i*100), Src: peer, Dst: G2HostV6, SPort: uint16(31000 + i), DPort: 53, Proto: 17, Payload: 40})
	}
	handshake(165_000, netip.MustParseAddr("2001:db8::10"), G2HostV6, 47000, 22)

	sort.SliceStable(fs, func(i, j int) bool { return fs[i].TS.Before(fs[j].TS) })
	return fs
}
