package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
