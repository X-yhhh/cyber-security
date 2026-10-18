package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedCaptureRequiresAuthorizedLiveParent(t *testing.T) {
	c := config{Environment: "authorized", CaptureScope: scopeAllInbound, Upload: &uploadConfig{}, AuthorizedUntil: time.Now().Add(time.Hour)}
	if err := validateManaged(c, 0, 42, 42, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*config, *int, *int, *bool){
		func(c *config, p, a *int, l *bool) { *p = 0 },
		func(c *config, p, a *int, l *bool) { *a = 43 },
		func(c *config, p, a *int, l *bool) { c.Environment = "lab" },
		func(c *config, p, a *int, l *bool) { c.CaptureScope = scopeService },
		func(c *config, p, a *int, l *bool) { c.Upload = nil },
		func(c *config, p, a *int, l *bool) { c.AuthorizedUntil = time.Now().Add(-time.Second) },
		func(c *config, p, a *int, l *bool) { *l = false },
	} {
		copy, parent, actual, live := c, 42, 42, true
		change(&copy, &parent, &actual, &live)
		if validateManaged(copy, 0, parent, actual, live) == nil {
			t.Fatal("accepted invalid managed capture")
		}
	}
}

func TestParentExitCancelsCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchParent(ctx, cancel, 42, func() int { return 1 })
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("orphan capture remained active")
	}
}

func TestManagedOutputRotatesCompleteRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	w, err := openOutput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	f := w.(*rotatingFile)
	f.limit = 8
	for i := 0; i < 20; i++ {
		if _, err := f.Write([]byte("{\"n\":1}\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(path + "*")
	if len(files) != 4 {
		t.Fatalf("files=%d", len(files))
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil || string(b) != "{\"n\":1}\n" || !strings.HasSuffix(string(b), "\n") {
			t.Fatalf("partial record %s", file)
		}
	}
}

func TestWatchAddressesStopsOnChange(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.168.1.20")}
	var calls atomic.Int32
	lookup := func(string, bool) ([]netip.Addr, error) {
		if calls.Add(1) < 3 {
			return []netip.Addr{netip.MustParseAddr("192.168.1.20")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.7")}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var changed atomic.Bool
	done := make(chan struct{})
	go func() { watchAddresses(ctx, cancel, "en0", want, time.Millisecond, lookup, &changed); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("地址变化后应结束")
	}
	if !changed.Load() || ctx.Err() == nil || calls.Load() != 3 {
		t.Fatalf("changed=%v ctx=%v calls=%d", changed.Load(), ctx.Err(), calls.Load())
	}
}

func TestWatchAddressesKeepsRunningWhenStable(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.168.1.20")}
	lookup := func(string, bool) ([]netip.Addr, error) { return want, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var changed atomic.Bool
	watchAddresses(ctx, func() {}, "en0", want, time.Millisecond, lookup, &changed)
	if changed.Load() {
		t.Fatal("地址未变不应结束")
	}
	// 接口消失（断网、关闭 Wi-Fi）同样结束，不能继续空采。
	gone := func(string, bool) ([]netip.Addr, error) { return nil, nil }
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	watchAddresses(ctx2, cancel2, "en0", want, time.Millisecond, gone, &changed)
	if !changed.Load() {
		t.Fatal("接口无可用地址应结束")
	}
}

func TestSameAddressesIgnoresOrder(t *testing.T) {
	a := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	b := []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")}
	if !sameAddresses(a, b) || sameAddresses(a, b[:1]) || sameAddresses(a, []netip.Addr{a[0], a[0]}) {
		t.Fatal("地址集合比较错误")
	}
}
