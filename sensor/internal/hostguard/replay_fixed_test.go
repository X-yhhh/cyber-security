package hostguard

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRegisteredFixedOffsetPreservesCausalObservations(t *testing.T) {
	path, _ := replayFixture(t)
	var original, shifted []Observation
	start := epoch
	reference, _ := New(config(&original))
	if e := reference.Tick(start); e != nil {
		t.Fatal(e)
	}
	if e := ReadPCAP(path, reference); e != nil {
		t.Fatal(e)
	}
	clock := &fakeClock{now: epoch.Add(1000 * time.Hour).Add(-time.Second)}
	offset := 1000 * time.Hour
	candidate, _ := New(config(&shifted))
	res, e := ReplayPCAP(context.Background(), path, candidate, ReplayOptions{Clock: clock, CaptureStart: start, FixedOffset: &offset})
	if e != nil {
		t.Fatal(e)
	}
	if res.Offset != offset || len(original) != len(shifted) {
		t.Fatal("registered offset/sequence changed")
	}
	for i := range original {
		want := original[i]
		want.EmittedAt = time.Time{}
		got := unshift(shifted[i], offset)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("causal difference at %d", i)
		}
	}
}
func TestRegisteredReplayChecksRevocationDuringWarmup(t *testing.T) {
	path, _ := replayFixture(t)
	var output []Observation
	e, _ := New(config(&output))
	clock := &fakeClock{now: epoch}
	offset := time.Minute
	checks := 0
	stop := errors.New("LAB_REVOKED")
	_, err := ReplayPCAP(context.Background(), path, e, ReplayOptions{Clock: clock, CaptureStart: epoch, FixedOffset: &offset, Check: func() error {
		checks++
		if checks == 3 {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) || len(output) > 0 || clock.now.After(epoch.Add(time.Second)) {
		t.Fatal("revocation did not stop warmup")
	}
}
