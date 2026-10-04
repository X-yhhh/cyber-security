package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

type fakeSubmitter struct {
	mu    sync.Mutex
	keys  []string
	seqs  []int64
	sizes []int
	errs  []error // 依次返回；用尽后返回 nil
}

func (f *fakeSubmitter) SubmitBatch(_ context.Context, key string, b uplink.Batch) (uplink.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys, f.seqs, f.sizes = append(f.keys, key), append(f.seqs, b.Sequence), append(f.sizes, len(b.Records))
	if len(f.errs) > 0 {
		e := f.errs[0]
		f.errs = f.errs[1:]
		return uplink.Receipt{}, e
	}
	return uplink.Receipt{TotalCount: int64(len(b.Records))}, nil
}

func readyRecords(n int, from int) []feature.Record {
	rs := make([]feature.Record, 0, n)
	for i := 0; i < n; i++ {
		rs = append(rs, feature.Record{RecordKey: "b:" + itoaTest(from+i), Status: feature.StatusReady, AF: "ipv4",
			Viewpoint: "responder", Features: &feature.Features{Proto: "tcp", Service: "-"}})
	}
	return append(rs, feature.Record{RecordKey: "b:skip", Status: feature.StatusWindowNotReady})
}

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	s := ""
	for v > 0 {
		s = string(rune('0'+v%10)) + s
		v /= 10
	}
	return s
}

func newTestUploader(t *testing.T, sub Submitter, spool int) *Uploader {
	t.Helper()
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := local()
	l.SpoolBatches = spool
	u := NewUploader(sub, st, l, "cfg-1")
	u.backoffStart, u.backoffMax = time.Millisecond, 4*time.Millisecond
	return u
}

func TestUploaderBatchesAndRetriesWithSameKey(t *testing.T) {
	sub := &fakeSubmitter{errs: []error{&uplink.Error{Class: uplink.Retryable}, &uplink.Error{Class: uplink.Retryable}}}
	u := newTestUploader(t, sub, 8)
	u.Add(readyRecords(700, 0)) // 500 满一批自动入队，余 200 留缓冲；非 ready 记录丢弃不计
	u.Close()
	if err := u.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 第一批重试两次：同一幂等键、同一序号；序号从 1 开始（后端 @Positive），第二批序号 2。
	want := []string{"sensor-1:cfg-1:1", "sensor-1:cfg-1:1", "sensor-1:cfg-1:1", "sensor-1:cfg-1:2"}
	if len(sub.keys) != 4 {
		t.Fatalf("提交次数错误: %v", sub.keys)
	}
	for i, k := range want {
		if sub.keys[i] != k {
			t.Fatalf("幂等键错误: %v", sub.keys)
		}
	}
	if sub.sizes[0] != 500 || sub.sizes[3] != 200 {
		t.Fatalf("批次大小错误: %v", sub.sizes)
	}
	if d, _ := u.TakeDropped(); d != 0 {
		t.Fatalf("不应丢弃: %d", d)
	}
}

func TestUploaderStopsOnStaleAndCountsOverflow(t *testing.T) {
	sub := &fakeSubmitter{errs: []error{&uplink.Error{Class: uplink.Stale, Code: "CONFIG_VERSION_STALE"}}}
	u := newTestUploader(t, sub, 1)
	u.Add(readyRecords(3, 0))
	u.Flush() // 入队（容量 1）
	u.Add(readyRecords(2, 10))
	u.Flush() // 队列满：丢弃新批次 2 条
	if d, q := u.TakeDropped(); d != 2 || q != 1 {
		t.Fatalf("溢出计数错误: dropped=%d queueMax=%d", d, q)
	}
	u.Close()
	if err := u.Run(context.Background()); !errors.Is(err, ErrUploadStopped) {
		t.Fatalf("Stale 应停止上报: %v", err)
	}
	if len(sub.keys) != 1 {
		t.Fatalf("Stale 不应重试: %v", sub.keys)
	}
}

// 停止时批次仍在重试（例如后端持续 5xx）：必须返回 ErrUploadStopped，不能当作正常退出。
func TestUploaderReportsUndeliveredOnCancel(t *testing.T) {
	errs := make([]error, 1000)
	for i := range errs {
		errs[i] = &uplink.Error{Class: uplink.Retryable, Status: 500, Code: "INTERNAL_ERROR"}
	}
	sub := &fakeSubmitter{errs: errs}
	u := newTestUploader(t, sub, 4)
	var logged int
	u.logf = func(string, ...any) { logged++ }
	u.Add(readyRecords(3, 0))
	u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := u.Run(ctx)
	if !errors.Is(err, ErrUploadStopped) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("停止时未送达应返回 ErrUploadStopped 且不包装 ctx 错误: %v", err)
	}
	if logged == 0 || sub.seqs[0] != 1 {
		t.Fatalf("重试应记录日志且序号从 1 开始: logged=%d seqs=%v", logged, sub.seqs)
	}
}
