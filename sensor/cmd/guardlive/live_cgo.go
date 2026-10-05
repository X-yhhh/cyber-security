//go:build cgo || windows

package main

import (
	"context"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"time"
)

// Windows 的 gopacket 通过系统调用加载 Npcap；只有 Unix libpcap 需要 cgo。
func capture(ctx context.Context, c config, e *hostguard.Engine, emit func(any) error) error {
	s, err := hostguard.OpenPCAPLive(c.Interface, c.AllowedInterfaces)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.ScopeService(c.LocalAddresses, c.PeerAddresses, c.ServicePort, c.ServiceEndpoint); err != nil {
		return err
	}
	return hostguard.RunLiveTrace(ctx, s, e, time.Now, func(v hostguard.LiveEvent) error { return emit(v) })
}
