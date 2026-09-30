// Package uplink 是传感器到后端 /api/v1/machine/sensors/{id} 的 HTTP 客户端。
//
// 只上报流级特征、心跳与健康计数；不上传载荷、地址或 pcap。机器凭据只在内存中保存，
// 不写日志、不进错误信息（Credential.String 已脱敏）。非回环地址必须使用 HTTPS。
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Credential 是一次性签发的机器凭据 mch_<clientId>.<secret>。
type Credential struct {
	ClientID int64
	body     string
}

var credentialPattern = regexp.MustCompile(`^mch_([1-9][0-9]*)\.([A-Za-z0-9_-]{40,64})$`)

// ParseCredential 校验并解析凭据字面量；失败时错误信息不回显输入。
func ParseCredential(raw string) (Credential, error) {
	m := credentialPattern.FindStringSubmatch(raw)
	if m == nil {
		return Credential{}, errors.New("机器凭据格式无效")
	}
	id, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return Credential{}, errors.New("机器凭据格式无效")
	}
	return Credential{ClientID: id, body: m[2]}, nil
}

// Literal 返回完整凭据字面量，只供密钥库写入使用。
func (c Credential) Literal() string { return fmt.Sprintf("mch_%d.%s", c.ClientID, c.body) }

func (c Credential) String() string { return fmt.Sprintf("mch_%d.<redacted>", c.ClientID) }

// Class 是错误处理类别。
type Class int

const (
	// Retryable：网络错误、5xx、429；按退避重试同一请求（同一幂等键）。
	Retryable Class = iota
	// Stale：配置版本失效或映射未批准；暂停上报，重新拉取配置。
	Stale
	// Fatal：身份/范围被拒、序号或幂等冲突、请求格式错误；停止上报并告警，不自动重试。
	Fatal
)

// Error 是后端拒绝或传输失败。Message 为后端返回的脱敏说明。
type Error struct {
	Status  int
	Code    string
	Message string
	Class   Class
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("uplink: %v", e.cause)
	}
	return fmt.Sprintf("uplink: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.cause }

func classify(status int, code string) Class {
	switch {
	case status == http.StatusTooManyRequests || status >= 500:
		return Retryable
	case code == "CONFIG_VERSION_STALE" || code == "MAPPING_NOT_APPROVED":
		return Stale
	default:
		return Fatal
	}
}

// Client 不保存会话状态；每个请求都携带机器凭据。
type Client struct {
	base     *url.URL
	sensorID int64
	cred     Credential
	http     *http.Client
}

// New 创建客户端。baseURL 为后端根地址；非回环主机必须是 https。
func New(baseURL string, sensorID int64, cred Credential, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("后端地址无效")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("非回环后端地址必须使用 HTTPS")
	}
	if sensorID < 1 {
		return nil, errors.New("传感器编号无效")
	}
	return &Client{base: u, sensorID: sensorID, cred: cred,
		http: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向，避免凭据被转发到其他主机
		}}}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// do 发送请求。okStatus 列出视为成功的状态码；成功时把 data 解到 out（可为 nil）。
func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, body any, out any,
	okStatus ...int) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, &Error{Class: Fatal, cause: err}
		}
		rd = bytes.NewReader(b)
	}
	u := c.base.JoinPath("/api/v1/machine/sensors", strconv.FormatInt(c.sensorID, 10), path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, &Error{Class: Fatal, cause: err}
	}
	req.Header.Set("Authorization", "Machine "+c.cred.Literal())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, &Error{Class: Retryable, cause: errors.New("请求失败或超时")}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env envelope
	parsed := len(raw) > 0 && json.Unmarshal(raw, &env) == nil
	// 失败信封一律按错误处理，即使状态码在成功列表中（例如请求校验失败也可能返回 422）。
	failed := parsed && (env.Error != nil || !env.Success)
	for _, s := range okStatus {
		if resp.StatusCode != s || failed {
			continue
		}
		if out != nil {
			if !parsed {
				return resp.StatusCode, &Error{Status: resp.StatusCode, Class: Fatal, Code: "RESPONSE_INVALID", Message: "响应不是成功信封"}
			}
			if err := json.Unmarshal(env.Data, out); err != nil {
				return resp.StatusCode, &Error{Status: resp.StatusCode, Class: Fatal, Code: "RESPONSE_INVALID", Message: "响应数据无法解析"}
			}
		}
		return resp.StatusCode, nil
	}
	e := &Error{Status: resp.StatusCode, Code: "HTTP_" + strconv.Itoa(resp.StatusCode)}
	if parsed && env.Error != nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
	}
	e.Class = classify(resp.StatusCode, e.Code)
	return resp.StatusCode, e
}

// Heartbeat 上报存活与能力声明。
func (c *Client) Heartbeat(ctx context.Context, observedAt time.Time, agentVersion string, capabilities map[string]any) error {
	_, err := c.do(ctx, http.MethodPost, "heartbeat", nil, map[string]any{
		"observedAt": observedAt.UTC(), "agentVersion": agentVersion, "capabilities": capabilities,
	}, nil, http.StatusNoContent)
	return err
}

// Config 是后端下发的已批准配置。interfaceScope/filterPolicy/samplingPolicy 是 JSON 字符串。
type Config struct {
	ConfigVersion          string    `json:"configVersion"`
	InterfaceScope         string    `json:"interfaceScope"`
	FilterPolicy           string    `json:"filterPolicy"`
	FlowWindowSeconds      int       `json:"flowWindowSeconds"`
	FeatureContractVersion string    `json:"featureContractVersion"`
	SamplingPolicy         string    `json:"samplingPolicy"`
	ActivatedAt            time.Time `json:"activatedAt"`
}

// FetchConfig 读取当前已批准配置。
func (c *Client) FetchConfig(ctx context.Context) (Config, error) {
	var cfg Config
	_, err := c.do(ctx, http.MethodGet, "config", nil, nil, &cfg, http.StatusOK)
	return cfg, err
}

// HealthWindow 是一个健康窗口的计数；约束见后端 SensorIngestService.healthWindow。
type HealthWindow struct {
	WindowStart   time.Time        `json:"windowStart"`
	WindowEnd     time.Time        `json:"windowEnd"`
	FlowsSeen     int64            `json:"flowsSeen"`
	FlowsEmitted  int64            `json:"flowsEmitted"`
	FlowsDropped  int64            `json:"flowsDropped"`
	QueueDepthMax int64            `json:"queueDepthMax"`
	CPUPercent    *float64         `json:"cpuPercent,omitempty"`
	MemoryBytes   *int64           `json:"memoryBytes,omitempty"`
	Errors        map[string]int64 `json:"errors"`
}

// Validate 在发送前复核后端的不变量，避免上报必然被拒的窗口。
func (h HealthWindow) Validate() error {
	switch {
	case !h.WindowEnd.After(h.WindowStart):
		return errors.New("健康窗口结束时间须晚于开始时间")
	case h.FlowsSeen < 0 || h.FlowsEmitted < 0 || h.FlowsDropped < 0 || h.QueueDepthMax < 0:
		return errors.New("健康计数不能为负")
	case h.FlowsEmitted > h.FlowsSeen || h.FlowsDropped > h.FlowsSeen-h.FlowsEmitted:
		return errors.New("健康计数违反 emitted ≤ seen、dropped ≤ seen − emitted")
	}
	for k := range h.Errors {
		if !errorCode.MatchString(k) {
			return errors.New("健康错误摘要键须为大写错误码")
		}
	}
	return nil
}

var errorCode = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

// SubmitHealth 上报健康窗口。
func (c *Client) SubmitHealth(ctx context.Context, h HealthWindow) error {
	if err := h.Validate(); err != nil {
		return &Error{Class: Fatal, cause: err}
	}
	if h.Errors == nil {
		h.Errors = map[string]int64{}
	}
	_, err := c.do(ctx, http.MethodPost, "health-windows", nil, h, nil, http.StatusNoContent)
	return err
}

// Batch 是流批次请求体（后端 FlowBatchBody）。Records 的 features 为按契约顺序序列化的对象。
type Batch struct {
	DataSourceID           int64       `json:"dataSourceId"`
	ConfigVersion          string      `json:"configVersion"`
	Sequence               int64       `json:"sequence"`
	ObservedAt             time.Time   `json:"observedAt"`
	SourceMappingVersion   string      `json:"sourceMappingVersion"`
	FeatureContractVersion string      `json:"featureContractVersion"`
	Records                []RecordOut `json:"records"`
}

// RecordOut 是单条上报记录。
type RecordOut struct {
	RecordKey      string          `json:"recordKey"`
	FlowStartAt    time.Time       `json:"flowStartAt"`
	FlowEndAt      time.Time       `json:"flowEndAt"`
	ObservedAt     time.Time       `json:"observedAt"`
	DirectionBasis string          `json:"directionBasis"`
	Features       json.RawMessage `json:"features"`
	Viewpoint      string          `json:"viewpoint"`
	AddressFamily  string          `json:"addressFamily"`
	HandshakeSeen  bool            `json:"handshakeSeen"`
}

// MaxRecordsPerBatch 与后端上限一致。
const MaxRecordsPerBatch = 500

// Receipt 是后端批次回执。
type Receipt struct {
	ID            int64  `json:"id"`
	BatchKey      string `json:"batchKey"`
	Status        string `json:"status"`
	TotalCount    int64  `json:"totalCount"`
	AcceptedCount int64  `json:"acceptedCount"`
	RejectedCount int64  `json:"rejectedCount"`
	SequenceGap   bool   `json:"sequenceGap"`
}

// SubmitBatch 提交批次。201 新建、200 幂等重放、422 全部记录被拒都视为已送达（不重试），
// 被拒记录的原因已在后端落库；调用方按回执计数。
func (c *Client) SubmitBatch(ctx context.Context, idempotencyKey string, b Batch) (Receipt, error) {
	if len(b.Records) == 0 || len(b.Records) > MaxRecordsPerBatch {
		return Receipt{}, &Error{Class: Fatal, cause: errors.New("批次记录数须在 1-500 之间")}
	}
	var r Receipt
	_, err := c.do(ctx, http.MethodPost, "flow-batches", map[string]string{"Idempotency-Key": idempotencyKey},
		b, &r, http.StatusCreated, http.StatusOK, http.StatusUnprocessableEntity)
	return r, err
}
