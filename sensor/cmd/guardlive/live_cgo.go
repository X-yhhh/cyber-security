//go:build cgo || windows

package main

import (
	"context"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// Windows 的 gopacket 通过系统调用加载 Npcap；只有 Unix libpcap 需要 cgo。
// all_inbound_tcp 只绑定本机登记地址；service 继续绑定登记对端与服务端口。
func capture(ctx context.Context, c config, e *hostguard.Engine, emit func(any) error, observe func(hostguard.LiveSample)) error {
	s, err := hostguard.OpenPCAPLive(c.Interface, c.AllowedInterfaces)
	if err != nil {
		return err
	}
	defer s.Close()
	if c.CaptureScope == scopeAllInbound {
		err = s.ScopeAllInbound(c.LocalAddresses)
	} else {
		err = s.ScopeService(c.LocalAddresses, c.PeerAddresses, c.ServicePort, c.ServiceEndpoint)
	}
	if err != nil {
		return err
	}
	return hostguard.RunLiveObserved(ctx, s, e, time.Now, func(v hostguard.LiveEvent) error { return emit(v) }, observe)
}
