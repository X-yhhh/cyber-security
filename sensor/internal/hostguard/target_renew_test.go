package hostguard

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 登记模式的固定租约剩余不足 time.Second 时换发新引用，保证租约不会在调用方超时内途中过期。
func TestRegisteredLeaseRenewsBeforeTransitExpiry(t *testing.T) {
	var rows []Observation
	e, _ := New(config(&rows))
	push(t, e, pkt(0, false, true, false, 1))
	closeEngine(t, e)
	o := rows[0]
	o.Environment = "lab"
	zero := 0.
	o.Quality.ClockSkewMs = &zero
	base := o.LastPacketAt
	now := base
	scope := TargetScope{AssetID: o.AssetID, SensorID: o.SensorID, BootID: o.BootID, CaptureScopeID: o.CaptureScopeID, Environment: "lab",
		ExecutorBootID: NewID(), KeyEpoch: 1, LocalAddresses: []netip.Addr{host},
		CollectorCertSHA256: strings.Repeat("aa", 32), ExecutorCertSHA256: strings.Repeat("bb", 32)}
	registered := 0
	r, err := NewRegisteredTargetRegistry(scope, func() time.Time { return now }, func(TargetBinding, Endpoints, TargetLease) error { registered++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	end := Endpoints{netip.AddrPortFrom(host, 80), netip.AddrPortFrom(peer, 40000), 6}
	at := func(d time.Duration) TargetLease {
		now = base.Add(d)
		// 整条观察平移到新包时刻，特征与时间关系不变。
		v := o
		v.FirstSeenAt, v.LastPacketAt, v.AsOf, v.EmittedAt = o.FirstSeenAt.Add(d), now, now, o.EmittedAt.Add(d)
		l, err := r.issue(v, end)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	first := at(0)
	same := at(15*time.Second - LeaseRenewMargin - time.Millisecond)
	if same != first {
		t.Fatalf("lease with enough remaining life must be reused: %+v %+v", first, same)
	}
	renewed := at(15*time.Second - LeaseRenewMargin + time.Millisecond)
	if renewed.Ref == first.Ref || !renewed.ExpiresAt.Equal(now.Add(15*time.Second)) || registered != 2 {
		t.Fatalf("near-expiry lease must be reissued and registered: %+v registered=%d", renewed, registered)
	}
	if renewed.ExpiresAt.Sub(now) < LeaseRenewMargin {
		t.Fatal("reissued lease would still expire in transit")
	}
	binding := Binding(o, scope.ExecutorBootID)
	if _, err := r.resolve(first.Ref, binding); err != nil {
		t.Fatal("old reference must stay resolvable until its own expiry:", err)
	}
	now = first.ExpiresAt
	if _, err := r.resolve(first.Ref, binding); err == nil {
		t.Fatal("old reference resolvable after expiry")
	}
	if _, err := r.resolve(renewed.Ref, binding); err != nil {
		t.Fatal("old expiry removed the new mapping:", err)
	}
	if again := at(15*time.Second + time.Millisecond); again.Ref != renewed.Ref {
		t.Fatalf("new reference must still be reused after old expiry: %+v", again)
	}
}
