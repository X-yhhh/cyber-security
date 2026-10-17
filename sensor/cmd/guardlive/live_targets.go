package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/guardlab"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// liveTargetConfig 不持有执行器凭据；只向回环 mTLS 解析器请求已登记对端的短期引用。
// 扫描端口映射 peer_inbound，服务端口映射 peer_service；拒绝扩大到未捕获端口。
type liveTargetConfig struct {
	TLS          guardlab.TLSConfig `json:"tls"`
	InboundPorts []uint16           `json:"inboundPorts"`
}

func liveLease(c config) (func(hostguard.Observation, hostguard.Endpoints) (string, time.Time, error), error) {
	if c.Environment != "lab" || c.CaptureScope != scopeLabPeer || c.Lab != nil || c.Upload == nil {
		return nil, fmt.Errorf("现场目标租约必须绑定 lab 实时上传")
	}
	for _, p := range c.LiveTargets.InboundPorts {
		if !slices.Contains(c.ServicePorts, p) {
			return nil, fmt.Errorf("目标范围超出采集端口")
		}
	}
	client, err := guardlab.NewTargetClient(c.LiveTargets.TLS)
	if err != nil {
		return nil, err
	}
	return func(o hostguard.Observation, ep hostguard.Endpoints) (string, time.Time, error) {
		if o.Direction != "inbound" || ep.Local.Addr() != c.LocalAddresses[0] || ep.Peer.Addr() != c.PeerAddresses[0] || !slices.Contains(c.ServicePorts, ep.Local.Port()) {
			return "", time.Time{}, hostguard.ErrTarget
		}
		scope := "peer_service"
		if slices.Contains(c.LiveTargets.InboundPorts, ep.Local.Port()) {
			scope = "peer_inbound"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		lease, err := client.Lease(ctx, o, ep, scope)
		if err != nil || lease.Ref == "" || !lease.ExpiresAt.After(o.LastPacketAt) || lease.ExpiresAt.After(o.LastPacketAt.Add(15*time.Second)) {
			return "", time.Time{}, hostguard.ErrTarget
		}
		return lease.Ref, lease.ExpiresAt, nil
	}, nil
}
