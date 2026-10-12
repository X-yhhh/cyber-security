package hostguard

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 多连接只能复用同一已授权范围的固定租约；新包不能延长已登记的截止时间。
func TestRegisteredLeaseUsesScopeWithoutExtendingDeadline(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	closeEngine(t, e)
	o := rows[0]
	o.Environment = "lab"
	zero := 0.0
	o.Quality.ClockSkewMs = &zero
	now := o.LastPacketAt.Add(time.Second)
	scope := TargetScope{AssetID: o.AssetID, SensorID: o.SensorID, BootID: o.BootID,
		CaptureScopeID: o.CaptureScopeID, Environment: "lab", ExecutorBootID: NewID(), KeyEpoch: 1,
		LocalAddresses: []netip.Addr{host}, CollectorCertSHA256: strings.Repeat("a", 64), ExecutorCertSHA256: strings.Repeat("b", 64)}
	calls := 0
	r, err := NewRegisteredTargetRegistry(scope, func() time.Time { return now }, func(TargetBinding, Endpoints, TargetLease) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(port uint16, peerPort uint16, targetScope string) TargetLease {
		t.Helper()
		o.ServicePort = &port
		o.FirstSeenAt = now.Add(-time.Duration(o.Features.ElapsedMs * 1e6))
		o.AsOf, o.LastPacketAt = now, now
		o.EmittedAt = now
		l, err := r.issueForScope(o, Endpoints{netip.AddrPortFrom(host, port), netip.AddrPortFrom(peer, peerPort), 6}, targetScope)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	first := issue(80, 40000, "peer_inbound")
	now = now.Add(time.Second)
	second := issue(443, 40001, "peer_inbound")
	if first != second || calls != 1 {
		t.Fatal("同一入站范围被连接端口拆分或截止时间被延长")
	}
	service := issue(80, 40002, "peer_service")
	if service.Ref == first.Ref {
		t.Fatal("不同执行范围共用引用")
	}
	if issue(80, 40003, "peer_service") != service {
		t.Fatal("临时端口拆分同一服务范围")
	}
	if issue(443, 40004, "peer_service").Ref == service.Ref {
		t.Fatal("不同服务端口共用引用")
	}
	now = first.ExpiresAt
	renewed := issue(443, 40005, "peer_inbound")
	if renewed.Ref == first.Ref || !renewed.ExpiresAt.After(first.ExpiresAt) {
		t.Fatal("过期后没有独立新引用")
	}
	if _, err := r.resolve(first.Ref, bindingForScope(o, scope.ExecutorBootID, "peer_inbound")); err == nil {
		t.Fatal("过期引用仍可解析")
	}
}
