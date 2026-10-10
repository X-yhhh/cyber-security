package guardup

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

func windows() bool { return runtime.GOOS == "windows" }

// NewUUID 生成随机小写 UUIDv4。
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

// SpoolMeta 绑定一个 spool 目录的身份；同目录不得换 boot、配置或契约后继续追加。
type SpoolMeta struct {
	SensorID        string `json:"sensorId"`
	BootID          string `json:"bootId"`
	ConfigID        string `json:"configId"`
	ContractVersion string `json:"contractVersion"`
	ProfileSha256   string `json:"profileSha256"`
}

// Batch 与 POST observation-batches 请求体逐字段对应。
type Batch struct {
	BatchID         string            `json:"batchId"`
	BootID          string            `json:"bootId"`
	Sequence        int64             `json:"sequence"`
	ConfigID        string            `json:"configId"`
	ContractVersion string            `json:"contractVersion"`
	ProfileSha256   string            `json:"profileSha256"`
	Observations    []json.RawMessage `json:"observations"`
}

// BatchResult 是 202 响应的数据部分。
type BatchResult struct {
	BatchID        string `json:"batchId"`
	Status         string `json:"status"`
	AcceptedCount  int    `json:"acceptedCount"`
	RejectedCount  int    `json:"rejectedCount"`
	DuplicateCount int    `json:"duplicateCount"`
	Rejections     []struct {
		ObservationID *string `json:"observationId"`
		Code          string  `json:"code"`
	} `json:"rejections"`
}

// Spool 是按 boot 分目录的持久批次队列。批次封口时先 fsync 原字节再进入发送队列，
// 收到 202 后再 fsync 回执；重启时未确认批次按 sequence 顺序重发同一字节。
type Spool struct {
	mu       sync.Mutex
	dir      string
	meta     SpoolMeta
	maxBatch int
	buffer   []json.RawMessage
	since    time.Time
	next     int64
	acked    map[int64]bool
	pending  []int64
	sealedAt map[int64]time.Time
}

var batchName = regexp.MustCompile(`^batch-([0-9]{12})\.json$`)
var ackName = regexp.MustCompile(`^ack-([0-9]{12})\.json$`)

// OpenSpool 打开或创建 root/<bootId>。已存在时 meta 必须完全一致，否则拒绝，防止序号跨 boot 混用。
func OpenSpool(root string, meta SpoolMeta, maxBatch int) (*Spool, error) {
	if !filepath.IsAbs(root) || !uuidPattern.MatchString(meta.BootID) || !uuidPattern.MatchString(meta.ConfigID) || !uuidPattern.MatchString(meta.SensorID) {
		return nil, errors.New("spool 目录或身份无效")
	}
	if maxBatch < 1 || maxBatch > 100 {
		return nil, errors.New("批次上限必须为 1..100")
	}
	dir := filepath.Join(root, meta.BootID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, meta: meta, maxBatch: maxBatch, next: 1, acked: map[int64]bool{}, sealedAt: map[int64]time.Time{}}
	metaPath := filepath.Join(dir, "meta.json")
	if b, err := os.ReadFile(metaPath); err == nil {
		var old SpoolMeta
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&old) != nil || old != meta {
			return nil, errors.New("SPOOL_IDENTITY_MISMATCH")
		}
	} else if os.IsNotExist(err) {
		b, _ := json.Marshal(meta)
		if err := writeDurable(dir, "meta.json", b); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var sealed []int64
	for _, e := range entries {
		if m := batchName.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			sealed = append(sealed, n)
		} else if m := ackName.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			s.acked[n] = true
		}
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i] < sealed[j] })
	for i, n := range sealed {
		if n != int64(i+1) {
			return nil, errors.New("SPOOL_SEQUENCE_GAP")
		}
		if !s.acked[n] {
			s.pending = append(s.pending, n)
		}
	}
	for n := range s.acked {
		if n > int64(len(sealed)) {
			return nil, errors.New("SPOOL_ACK_WITHOUT_BATCH")
		}
	}
	s.next = int64(len(sealed)) + 1
	return s, nil
}

// Dir 返回本 boot 的 spool 目录。
func (s *Spool) Dir() string { return s.dir }

// Append 追加一条已编码观察；满批立即封口。
func (s *Spool) Append(obs json.RawMessage, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buffer) == 0 {
		s.since = now
	}
	s.buffer = append(s.buffer, append(json.RawMessage(nil), obs...))
	if len(s.buffer) >= s.maxBatch {
		return s.sealLocked(now)
	}
	return nil
}

// SealIfOlder 在未满批次等待超过 maxDelay 后封口，限制观察到上传的时延。
func (s *Spool) SealIfOlder(now time.Time, maxDelay time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buffer) > 0 && now.Sub(s.since) >= maxDelay {
		return s.sealLocked(now)
	}
	return nil
}

// Seal 立即封口未满批次（结束或排空时调用）。
func (s *Spool) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealLocked(time.Now())
}

func (s *Spool) sealLocked(now time.Time) error {
	if len(s.buffer) == 0 {
		return nil
	}
	b := Batch{BatchID: NewUUID(), BootID: s.meta.BootID, Sequence: s.next, ConfigID: s.meta.ConfigID,
		ContractVersion: s.meta.ContractVersion, ProfileSha256: s.meta.ProfileSha256, Observations: s.buffer}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err = writeDurable(s.dir, fmt.Sprintf("batch-%012d.json", s.next), raw); err != nil {
		return err
	}
	s.pending = append(s.pending, s.next)
	s.sealedAt[s.next] = now
	s.next++
	s.buffer = nil
	return nil
}

// Next 返回最早的未确认批次原字节；没有时 ok=false。
func (s *Spool) Next() (seq int64, body []byte, batch Batch, ok bool, err error) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return 0, nil, Batch{}, false, nil
	}
	seq = s.pending[0]
	s.mu.Unlock()
	body, err = os.ReadFile(filepath.Join(s.dir, fmt.Sprintf("batch-%012d.json", seq)))
	if err != nil {
		return 0, nil, Batch{}, false, err
	}
	if err = json.Unmarshal(body, &batch); err != nil || batch.Sequence != seq || batch.BootID != s.meta.BootID {
		return 0, nil, Batch{}, false, errors.New("SPOOL_BATCH_CORRUPT")
	}
	return seq, body, batch, true, nil
}

// Ack 持久记录回执并出队。只能确认队首，保证 sequence 严格按序确认。
func (s *Spool) Ack(seq int64, result []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 || s.pending[0] != seq {
		return errors.New("SPOOL_ACK_OUT_OF_ORDER")
	}
	if err := writeDurable(s.dir, fmt.Sprintf("ack-%012d.json", seq), result); err != nil {
		return err
	}
	s.acked[seq] = true
	s.pending = s.pending[1:]
	return nil
}

// SealedAt 返回本进程内封口时刻；重启前封口的批次没有记录。
func (s *Spool) SealedAt(seq int64) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sealedAt[seq]
	delete(s.sealedAt, seq)
	return t, ok
}

// State 返回已封口批次数、未确认批次数、内存中未封口观察数与最后连续确认序号。
func (s *Spool) State() (sealed, pending, buffered int, lastAcked int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed = int(s.next - 1)
	pending = len(s.pending)
	buffered = len(s.buffer)
	lastAcked = s.next - 1
	if len(s.pending) > 0 {
		lastAcked = s.pending[0] - 1
	}
	return
}

// writeDurable 以临时文件 + fsync + 原子改名 + 目录 fsync 写入，已有同名文件则拒绝覆盖。
func writeDurable(dir, name string, b []byte) error {
	final := filepath.Join(dir, name)
	if _, err := os.Lstat(final); err == nil {
		return errors.New("SPOOL_FILE_EXISTS")
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), final); err != nil {
		return err
	}
	if windows() {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
