// Package guardup 是 host-guard v5 传感器到后端 /api/v2/machine/sensors/{id} 的上传通道。
//
// 传输固定为 HTTPS/TLS 1.3，强制出示传感器客户端证书（mTLS），同时携带 v2 机器凭据 Bearer mch_…；
// 不继承代理环境、不跟随重定向。观察批次先落本地 spool 再发送，重试复用同一 batchId、sequence 与
// Idempotency-Key 的原字节，服务端按幂等语义返回原结果，因此中断重连不丢也不重。
// 凭据、私钥与原始端点都不写入日志或错误信息。
package guardup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ClientConfig 中的文件路径必须是本机绝对普通文件；私钥与凭据文件只允许属主读写。
type ClientConfig struct {
	BaseURL         string        `json:"baseUrl"`
	SensorID        string        `json:"-"`
	CAFile          string        `json:"caFile"`
	CertificateFile string        `json:"certificateFile"`
	KeyFile         string        `json:"keyFile"`
	CredentialFile  string        `json:"credentialFile"`
	Timeout         time.Duration `json:"-"`
}

// Error 是后端拒绝或传输失败；Message 只含后端返回的脱敏说明。
type Error struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
	cause     error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("guardup: 传输失败: %v", e.cause)
	}
	return fmt.Sprintf("guardup: HTTP %d %s", e.Status, e.Code)
}
func (e *Error) Unwrap() error { return e.cause }

// Retryable 判断错误是否可以用同一请求重试。
func Retryable(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Retryable
}

// Client 不保存会话状态；每个请求都携带机器凭据。
type Client struct {
	base     *url.URL
	sensorID string
	token    string
	http     *http.Client
}

var credentialPattern = regexp.MustCompile(`^mch_[1-9][0-9]*\.[A-Za-z0-9_-]{40,64}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// privateFile 只接受绝对路径、非符号链接的普通文件；secret=true 时还要求属主专用权限。
func privateFile(path string, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("PRIVATE_FILE_REQUIRED")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("PRIVATE_FILE_REQUIRED")
	}
	if secret && !windows() && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("PRIVATE_FILE_PERMISSIONS_INVALID")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("PRIVATE_FILE_REQUIRED")
	}
	return b, nil
}

// NewClient 建立 mTLS 客户端。只接受 https；服务端证书由 CAFile 校验，客户端证书必须存在。
func NewClient(c ClientConfig) (*Client, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("后端地址必须是不含路径的 https 根地址")
	}
	if !uuidPattern.MatchString(c.SensorID) {
		return nil, errors.New("传感器编号必须为小写 UUID")
	}
	ca, err := privateFile(c.CAFile, false)
	if err != nil {
		return nil, fmt.Errorf("CA 文件: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("CA 文件无效")
	}
	certPEM, err := privateFile(c.CertificateFile, false)
	if err != nil {
		return nil, fmt.Errorf("客户端证书: %w", err)
	}
	keyPEM, err := privateFile(c.KeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("客户端私钥: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("客户端证书/私钥不匹配或无效")
	}
	raw, err := privateFile(c.CredentialFile, true)
	if err != nil {
		return nil, fmt.Errorf("机器凭据: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if !credentialPattern.MatchString(token) {
		return nil, errors.New("机器凭据格式无效")
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: c.Timeout, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	u.Path = ""
	return &Client{base: u, sensorID: c.SensorID, token: token, http: &http.Client{Timeout: c.Timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type envelope struct {
	RequestID string          `json:"requestId"`
	Data      json.RawMessage `json:"data"`
	Error     *struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}

// do 发送一次请求；成功状态为 ok 时把 data 解到 out。网络错误、408、429、5xx 可重试，其余 4xx 不重试。
func (c *Client) do(ctx context.Context, method, op, key string, body []byte, ok int, out any) error {
	u := c.base.JoinPath("/api/v2/machine/sensors", c.sensorID, op)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return &Error{cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Retryable: ctx.Err() == nil, cause: errors.New("连接或 TLS 失败")}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &Error{Status: resp.StatusCode, Retryable: true, cause: errors.New("读取响应失败")}
	}
	retry := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	var env envelope
	if json.Unmarshal(b, &env) != nil {
		return &Error{Status: resp.StatusCode, Code: "INVALID_RESPONSE", Retryable: retry}
	}
	if resp.StatusCode != ok || env.Error != nil {
		e := &Error{Status: resp.StatusCode, Code: "UNEXPECTED_STATUS", Retryable: retry}
		if env.Error != nil {
			e.Code, e.Message = env.Error.Code, env.Error.Message
			e.Retryable = retry || env.Error.Retryable && resp.StatusCode >= 500
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return &Error{Status: resp.StatusCode, Code: "INVALID_RESPONSE"}
		}
	}
	return nil
}

// RemoteConfig 是 GET /machine/sensors/{id}/config 的数据部分。
type RemoteConfig struct {
	ConfigID   string `json:"configId"`
	ConfigHash string `json:"configHash"`
	ServerTime string `json:"serverTime"`
	Config     struct {
		ContractVersion      string   `json:"contractVersion"`
		ProfileSha256        string   `json:"profileSha256"`
		CaptureHealthVersion string   `json:"captureHealthVersion"`
		InterfaceIDs         []string `json:"interfaceIds"`
		CaptureScopeID       string   `json:"captureScopeId"`
		AddressFamily        string   `json:"addressFamily"`
		BuildSha256          string   `json:"buildSha256"`
		Limits               struct {
			MaxBatchSize int `json:"maxBatchSize"`
		} `json:"limits"`
	} `json:"config"`
}

// Config 读取当前已批准的传感器配置。
func (c *Client) Config(ctx context.Context) (RemoteConfig, error) {
	var r RemoteConfig
	err := c.do(ctx, http.MethodGet, "config", "", nil, http.StatusOK, &r)
	return r, err
}
