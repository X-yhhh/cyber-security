// Package feature 把已完成的流按特征规格 §1.2、§2、§3 构造成 v4 raw features。
//
// 处理顺序与后端 Java FeatureBuilder 逐步一致（G2 对拍依赖它）：地址分类 → 入窗（迟到拒绝且不入窗）
// → 逐流值校验（非法值照常占窗口位，但自身不输出特征）→ 窗口未满不输出 → 计数。
package feature

import "net/netip"

// Class 是地址分类结论。Excluded 非空表示排除，其余字段为空。
type Class struct {
	Excluded  string
	AF        string // ipv4、ipv6
	Viewpoint string // responder、initiator
}

// AddressPolicy 判定排除、地址族与本机视角（§1.2）。只比较 IP 字面量，不做 DNS 查询。
type AddressPolicy struct {
	local map[netip.Addr]bool
	bcast map[netip.Addr]bool
}

// NewAddressPolicy 以本机在授权接口上的地址和接口 IPv4 子网（用于定向广播判定）构造。
func NewAddressPolicy(local []netip.Addr, subnets []netip.Prefix) *AddressPolicy {
	p := &AddressPolicy{local: map[netip.Addr]bool{}, bcast: map[netip.Addr]bool{}}
	p.AddLocal(local, subnets)
	return p
}

// AddLocal 追加本机地址与子网；旧地址保留，保证已建流的视角判定不变（IPv6 临时地址会轮换）。
func (p *AddressPolicy) AddLocal(local []netip.Addr, subnets []netip.Prefix) {
	for _, a := range local {
		p.local[a] = true
	}
	for _, s := range subnets {
		if !s.Addr().Is4() || s.Bits() < 1 || s.Bits() > 30 {
			continue
		}
		b := s.Masked().Addr().As4()
		host := ^uint32(0) >> s.Bits()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
		p.bcast[netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})] = true
	}
}

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Classify 分类一条流；检查顺序与 Java AddressPolicy.classify 相同。
func (p *AddressPolicy) Classify(initiator, responder netip.Addr) Class {
	switch {
	case !initiator.IsValid() || !responder.IsValid() || initiator.Is4() != responder.Is4():
		return Class{Excluded: "invalid_address"}
	case responder.IsMulticast():
		return Class{Excluded: "multicast_destination"}
	case responder == limitedBroadcast || p.bcast[responder]:
		return Class{Excluded: "broadcast_destination"}
	case responder.IsLoopback():
		return Class{Excluded: "loopback_destination"}
	case responder.IsUnspecified():
		return Class{Excluded: "unspecified_destination"}
	}
	af := "ipv4"
	if responder.Is6() {
		af = "ipv6"
	}
	// 两端都是本机时按 responder 处理，与训练端 recompute_ct 以 dstip 为传感器主机的口径一致。
	if p.local[responder] {
		return Class{AF: af, Viewpoint: "responder"}
	}
	if p.local[initiator] {
		return Class{AF: af, Viewpoint: "initiator"}
	}
	return Class{Excluded: "no_local_endpoint"}
}
