//go:build cgo

package main

import (
	"context"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"time"
)

func capture(ctx context.Context, c config, e *hostguard.Engine, emit func(any) error) error {
	s, err := hostguard.OpenPCAPLive(c.Interface, c.AllowedInterfaces)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.Scope(c.LocalAddresses, c.PeerAddresses, c.ServicePort); err != nil {
		return err
	}
	return hostguard.RunLiveTrace(ctx, s, e, time.Now, func(v hostguard.LiveEvent) error { return emit(v) })
}
