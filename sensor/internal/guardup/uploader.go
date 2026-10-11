package guardup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capturehealth"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
	"github.com/xyh/cyber-security/sensor/internal/jcs"
)

// Options 配置一个 boot 的上传器。Remote 必须已经过 VerifyRemote 校验。
type Options struct {
	Client         *Client
	Spool          *Spool
	Remote         RemoteConfig
	BootID         string
	Version        string
	MaxDelay       time.Duration
	HeartbeatEvery time.Duration
	MaxHealthQueue int
	Now            func() time.Time
	Backoff        func(attempt int) time.Duration
}

// Stats 是去敏的上传统计，可写入运行摘要。
type Stats struct {
	SealedBatches   int            `json:"sealedBatches"`
	AckedBatches    int            `json:"ackedBatches"`
	PendingBatches  int            `json:"pendingBatches"`
	Accepted        int            `json:"accepted"`
	Duplicates      int            `json:"duplicates"`
	Rejected        int            `json:"rejected"`
	RejectionCodes  map[string]int `json:"rejectionCodes"`
	Retries         int            `json:"retries"`
	Heartbeats      int            `json:"heartbeats"`
	HealthSent      int            `json:"healthSent"`
	HealthStatuses  map[string]int `json:"healthStatuses"`
	HealthQueueMax  int            `json:"healthQueueMax"`
	LastClockSkewMs *int64         `json:"lastClockSkewMs"`
	AckLatencyMaxMs int64          `json:"ackLatencyMaxMs"`
	FatalCode       string         `json:"fatalCode,omitempty"`
}

// Uploader 串行发送：先健康窗口（10 秒时效），再按 sequence 顺序逐个发送观察批次，同一时刻只有一个批次在途。
type Uploader struct {
	o      Options
	mu     sync.Mutex
	health []capturehealth.Window
	fatal  error
	stats  Stats
	skew   int64
	skewAt time.Time
	wake   chan struct{}
}

// VerifyRemote 对已批准配置做 fail-closed 核对：契约、profile、健康版本、捕获域、地址族与程序摘要必须与本机一致。
func VerifyRemote(r RemoteConfig, captureScopeID, addressFamily, buildSha256 string) error {
	c := r.Config
	switch {
	case !uuidPattern.MatchString(r.ConfigID) || len(r.ConfigHash) != 64:
		return errors.New("CONFIG_INACTIVE")
	case c.ContractVersion != hostguard.Version || c.ProfileSha256 != hostguard.FeatureProfileSHA256:
		return errors.New("CONTRACT_UNSUPPORTED")
	case c.CaptureHealthVersion != capturehealth.Version:
		return errors.New("HEALTH_VERSION_UNSUPPORTED")
	case c.CaptureScopeID != captureScopeID || c.AddressFamily != addressFamily:
		return errors.New("SCOPE_DENIED")
	case c.BuildSha256 != buildSha256:
		return errors.New("BUILD_NOT_APPROVED")
	case c.Limits.MaxBatchSize < 1 || c.Limits.MaxBatchSize > 100:
		return errors.New("CAPACITY_EXCEEDED")
	}
	return nil
}

func New(o Options) (*Uploader, error) {
	if o.Client == nil || o.Spool == nil || !uuidPattern.MatchString(o.BootID) || o.Version == "" {
		return nil, errors.New("上传器参数不完整")
	}
	if o.MaxDelay == 0 {
		o.MaxDelay = 500 * time.Millisecond
	}
	if o.HeartbeatEvery == 0 {
		o.HeartbeatEvery = 15 * time.Second
	}
	if o.MaxHealthQueue == 0 {
		o.MaxHealthQueue = 4096
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Backoff == nil {
		o.Backoff = func(n int) time.Duration {
			return min(250*time.Millisecond<<min(n, 5), 5*time.Second)
		}
	}
	return &Uploader{o: o, wake: make(chan struct{}, 1), stats: Stats{RejectionCodes: map[string]int{}, HealthStatuses: map[string]int{}}}, nil
}

func (u *Uploader) signal() {
	select {
	case u.wake <- struct{}{}:
	default:
	}
}

func (u *Uploader) setFatal(err error) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.fatal == nil {
		u.fatal = err
		var e *Error
		if errors.As(err, &e) {
			u.stats.FatalCode = e.Code
		} else {
			u.stats.FatalCode = err.Error()
		}
	}
	return u.fatal
}

// Err 返回已发生的致命错误。
func (u *Uploader) Err() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.fatal
}

// Submit 把一条已编码观察写入 spool；上传器已致命失败时返回该错误，调用方应停止采集。
func (u *Uploader) Submit(obs []byte) error {
	if err := u.Err(); err != nil {
		return err
	}
	if err := u.o.Spool.Append(obs, u.o.Now()); err != nil {
		return u.setFatal(err)
	}
	u.signal()
	return nil
}

// SubmitHealth 排队一个健康窗口；队列超限视为致命，不静默丢弃以免掩盖缺口。
func (u *Uploader) SubmitHealth(w capturehealth.Window) error {
	u.mu.Lock()
	if u.fatal != nil {
		defer u.mu.Unlock()
		return u.fatal
	}
	if len(u.health) >= u.o.MaxHealthQueue {
		u.mu.Unlock()
		return u.setFatal(errors.New("HEALTH_QUEUE_OVERFLOW"))
	}
	u.health = append(u.health, w)
	u.stats.HealthQueueMax = max(u.stats.HealthQueueMax, len(u.health))
	u.mu.Unlock()
	u.signal()
	return nil
}

// Skew 返回 60 秒内由心跳测得的时钟偏差（毫秒）。
func (u *Uploader) Skew() (int64, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.skewAt.IsZero() || u.o.Now().Sub(u.skewAt) > time.Minute {
		return 0, false
	}
	return u.skew, true
}

// QueueDepth 返回未确认批次数与待发健康窗口数之和，供健康 metrics.queueMax 使用。
func (u *Uploader) QueueDepth() int64 {
	_, pending, _, _ := u.o.Spool.State()
	u.mu.Lock()
	defer u.mu.Unlock()
	return int64(pending + len(u.health))
}

// Stats 返回统计快照。
func (u *Uploader) Stats() Stats {
	sealed, pending, _, _ := u.o.Spool.State()
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.stats
	s.SealedBatches, s.PendingBatches = sealed, pending
	s.RejectionCodes = map[string]int{}
	for k, v := range u.stats.RejectionCodes {
		s.RejectionCodes[k] = v
	}
	s.HealthStatuses = map[string]int{}
	for k, v := range u.stats.HealthStatuses {
		s.HealthStatuses[k] = v
	}
	if !u.skewAt.IsZero() {
		v := u.skew
		s.LastClockSkewMs = &v
	}
	return s
}

func (u *Uploader) sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (u *Uploader) heartbeat(ctx context.Context) error {
	_, _, _, last := u.o.Spool.State()
	body := map[string]any{"bootId": u.o.BootID, "version": u.o.Version, "configHash": u.o.Remote.ConfigHash, "lastSequence": last, "clockSkewMs": nil}
	if v, ok := u.Skew(); ok {
		body["clockSkewMs"] = v
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var out struct {
		ServerTime string `json:"serverTime"`
	}
	sent := u.o.Now()
	if err = u.o.Client.do(ctx, http.MethodPost, "heartbeats", NewUUID(), raw, http.StatusOK, &out); err != nil {
		return err
	}
	received := u.o.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stats.Heartbeats++
	// 只有往返 ≤1 秒时才用中点估计偏差，否则视为不可信而不更新。
	if server, perr := time.Parse(time.RFC3339Nano, out.ServerTime); perr == nil && received.Sub(sent) <= time.Second {
		mid := sent.Add(received.Sub(sent) / 2)
		u.skew = int64(math.Round(float64(server.Sub(mid)) / float64(time.Millisecond)))
		u.skewAt = received
	}
	return nil
}

func (u *Uploader) sendBatch(ctx context.Context, seq int64, body []byte, b Batch) error {
	var r BatchResult
	if err := u.o.Client.do(ctx, http.MethodPost, "observation-batches", b.BatchID, body, http.StatusAccepted, &r); err != nil {
		return err
	}
	if r.BatchID != b.BatchID || r.AcceptedCount+r.RejectedCount+r.DuplicateCount != len(b.Observations) || r.AcceptedCount < 0 || r.RejectedCount < 0 || r.DuplicateCount < 0 {
		return &Error{Status: http.StatusAccepted, Code: "INVALID_BATCH_RESULT"}
	}
	raw, _ := json.Marshal(r)
	if err := u.o.Spool.Ack(seq, raw); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stats.AckedBatches++
	u.stats.Accepted += r.AcceptedCount
	u.stats.Duplicates += r.DuplicateCount
	u.stats.Rejected += r.RejectedCount
	for _, x := range r.Rejections {
		u.stats.RejectionCodes[x.Code]++
	}
	if at, ok := u.o.Spool.SealedAt(seq); ok {
		u.stats.AckLatencyMaxMs = max(u.stats.AckLatencyMaxMs, u.o.Now().Sub(at).Milliseconds())
	}
	return nil
}

func (u *Uploader) sendHealth(ctx context.Context, w capturehealth.Window) error {
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	want, err := jcs.SHA256(w)
	if err != nil {
		return err
	}
	var out struct {
		HealthWindowID     string `json:"healthWindowId"`
		VerificationStatus string `json:"verificationStatus"`
		ContentSha256      string `json:"contentSha256"`
	}
	if err = u.o.Client.do(ctx, http.MethodPost, "health-windows", w.HealthWindowID, raw, http.StatusOK, &out); err != nil {
		return err
	}
	// 服务端摘要与本地 JCS 不一致时哈希链必然断裂，按缺陷停止而不是继续上报。
	if out.HealthWindowID != w.HealthWindowID || out.ContentSha256 != want || out.VerificationStatus == "" {
		return &Error{Status: http.StatusOK, Code: "HEALTH_HASH_MISMATCH"}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.health = u.health[1:]
	u.stats.HealthSent++
	u.stats.HealthStatuses[out.VerificationStatus]++
	return nil
}

// Run 先完成首个心跳（登记 bootId），之后循环发送直到 ctx 结束或出现致命错误。
// 可重试错误按退避重发同一请求；不可重试错误（身份、范围、幂等冲突、格式）立即停止。
func (u *Uploader) Run(ctx context.Context) error {
	attempt := 0
	retry := func(err error) error {
		if !Retryable(err) {
			return u.setFatal(err)
		}
		u.mu.Lock()
		u.stats.Retries++
		u.mu.Unlock()
		d := u.o.Backoff(attempt)
		attempt++
		return u.sleep(ctx, d)
	}
	for {
		err := u.heartbeat(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = retry(err); err != nil {
			return err
		}
	}
	attempt = 0
	lastHeartbeat := u.o.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := u.Err(); err != nil {
			return err
		}
		if err := u.o.Spool.SealIfOlder(u.o.Now(), u.o.MaxDelay); err != nil {
			return u.setFatal(err)
		}
		u.mu.Lock()
		var w *capturehealth.Window
		if len(u.health) > 0 {
			v := u.health[0]
			w = &v
		}
		u.mu.Unlock()
		if w != nil {
			if err := u.sendHealth(ctx, *w); err != nil {
				if err = retry(err); err != nil {
					return err
				}
				continue
			}
			attempt = 0
			continue
		}
		if u.o.Now().Sub(lastHeartbeat) >= u.o.HeartbeatEvery {
			// 持续发送批次时也按期心跳，偏差测值才不会在长回放中过期；失败不阻塞数据发送。
			if err := u.heartbeat(ctx); err != nil && !Retryable(err) {
				return u.setFatal(err)
			}
			lastHeartbeat = u.o.Now()
		}
		seq, body, batch, ok, err := u.o.Spool.Next()
		if err != nil {
			return u.setFatal(err)
		}
		if ok {
			if err := u.sendBatch(ctx, seq, body, batch); err != nil {
				if err = retry(err); err != nil {
					return err
				}
				continue
			}
			attempt = 0
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-u.wake:
		case <-ticker.C:
		}
	}
}

// Drain 封口剩余观察并等待全部批次与健康窗口确认；Run 须仍在运行。超时或致命错误时返回错误，spool 保留可续传。
func (u *Uploader) Drain(ctx context.Context) error {
	if err := u.o.Spool.Seal(); err != nil {
		return u.setFatal(err)
	}
	u.signal()
	for {
		if err := u.Err(); err != nil {
			return err
		}
		_, pending, buffered, _ := u.o.Spool.State()
		u.mu.Lock()
		h := len(u.health)
		u.mu.Unlock()
		if pending == 0 && buffered == 0 && h == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("上传未排空: 待确认批次 %d、健康窗口 %d", pending, h)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
