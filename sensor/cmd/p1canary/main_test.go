package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestCanaryRejectsWideBindingPublicPeersAndUnboundedRuns(t *testing.T) {
	for _, tc := range []struct {
		bind, peer string
		duration   time.Duration
	}{{"0.0.0.0:49173", "192.0.2.1", time.Second}, {"127.0.0.1:49173", "127.0.0.2", time.Second}, {"10.0.0.1:22", "10.0.0.2", time.Second}, {"10.0.0.1:49173", "8.8.8.8", time.Second}, {"10.0.0.1:49173", "10.0.0.2", 4 * time.Minute}} {
		if err := serve(tc.bind, netip.MustParseAddr(tc.peer), tc.duration); err == nil {
			t.Fatal("未拒绝不安全测试范围")
		}
	}
}
