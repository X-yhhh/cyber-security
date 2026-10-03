//go:build cgo

package hostguard

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"slices"
	"time"
)

// PCAPLive 仅打开明确白名单中的 Ethernet/RAW IP 接口；非混杂、固定 IP 过滤、100ms超时。
// 本入口供未来授权服务集成；P2 不启动真实采集，不扩大旧 v4 的运行配置。
type PCAPLive struct{ h *pcap.Handle }

func OpenPCAPLive(iface string, allowed []string) (*PCAPLive, error) {
	if iface == "" || !slices.Contains(allowed, iface) {
		return nil, fmt.Errorf("接口未授权")
	}
	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	for _, err := range []error{in.SetSnapLen(256), in.SetPromisc(false), in.SetTimeout(100 * time.Millisecond)} {
		if err != nil {
			return nil, err
		}
	}
	h, err := in.Activate()
	if err != nil {
		return nil, err
	}
	if !supportedLink(h.LinkType()) {
		h.Close()
		return nil, fmt.Errorf("不支持的链路类型")
	}
	if err = h.SetBPFFilter("ip or ip6"); err != nil {
		h.Close()
		return nil, err
	}
	return &PCAPLive{h}, nil
}
func (s *PCAPLive) Close() { s.h.Close() }
func (s *PCAPLive) Next() ([]byte, gopacket.CaptureInfo, error) {
	b, c, err := s.h.ReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		err = ErrCaptureTimeout
	}
	if err == nil {
		return normalizeLink(b, c, s.h.LinkType())
	}
	return b, c, err
}
func (s *PCAPLive) Drops() (uint64, error) {
	v, err := s.h.Stats()
	if err != nil {
		return 0, err
	}
	return uint64(v.PacketsDropped + v.PacketsIfDropped), nil
}
