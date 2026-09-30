package uplink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const fakeCredentialBody = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123"

func testCred(t *testing.T) Credential {
	t.Helper()
	c, err := ParseCredential("mch_7." + fakeCredentialBody)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCredentialParsingAndRedaction(t *testing.T) {
	c := testCred(t)
	if c.ClientID != 7 || strings.Contains(c.String(), fakeCredentialBody) || c.Literal() != "mch_7."+fakeCredentialBody {
		t.Fatalf("凭据解析或脱敏错误: %s", c)
	}
	for _, bad := range []string{"", "mch_0." + fakeCredentialBody, "mch_7.short", "Machine mch_7." + fakeCredentialBody} {
		if _, err := ParseCredential(bad); err == nil || strings.Contains(err.Error(), fakeCredentialBody) {
			t.Fatalf("应拒绝且不回显: %q", bad)
		}
	}
}

func TestNewRequiresHTTPSForNonLoopback(t *testing.T) {
	c := testCred(t)
	if _, err := New("http://backend.example", 1, c, time.Second); err == nil {
		t.Fatal("非回环 http 应被拒绝")
	}
	for _, ok := range []string{"http://127.0.0.1:18080", "http://localhost:18080", "https://backend.example"} {
		if _, err := New(ok, 1, c, time.Second); err != nil {
			t.Fatalf("%s 应允许: %v", ok, err)
		}
	}
}

func envelopeJSON(data any) string {
	b, _ := json.Marshal(map[string]any{"success": true, "data": data, "requestId": "r"})
	return string(b)
}

func errorJSON(code string) string {
	b, _ := json.Marshal(map[string]any{"success": false, "error": map[string]string{"code": code, "message": "m"}, "requestId": "r"})
	return string(b)
}

func batch() Batch {
	return Batch{DataSourceID: 3, ConfigVersion: "cfg-1", Sequence: 0, ObservedAt: time.Now(),
		SourceMappingVersion: "m1", FeatureContractVersion: "unsw-nb15-flow-v4",
		Records: []RecordOut{{RecordKey: "boot:1", DirectionBasis: "initiator_to_responder", Features: json.RawMessage(`{}`),
			Viewpoint: "responder", AddressFamily: "ipv4"}}}
}

func TestSubmitBatchStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		class  *Class // nil 表示成功
	}{
		{201, envelopeJSON(map[string]any{"id": 1, "acceptedCount": 1, "totalCount": 1}), nil},
		{200, envelopeJSON(map[string]any{"id": 1, "acceptedCount": 1, "totalCount": 1}), nil},
		{422, envelopeJSON(map[string]any{"id": 2, "acceptedCount": 0, "rejectedCount": 1, "totalCount": 1}), nil},
		{422, errorJSON("INVALID_REQUEST"), ptr(Fatal)},
		{409, errorJSON("CONFIG_VERSION_STALE"), ptr(Stale)},
		{409, errorJSON("MAPPING_NOT_APPROVED"), ptr(Stale)},
		{409, errorJSON("SEQUENCE_CONFLICT"), ptr(Fatal)},
		{401, errorJSON("MACHINE_IDENTITY_REJECTED"), ptr(Fatal)},
		{503, "", ptr(Retryable)},
		{429, "", ptr(Retryable)},
	}
	for _, c := range cases {
		var gotAuth, gotKey string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
			if r.URL.Path != "/api/v1/machine/sensors/9/flow-batches" {
				t.Errorf("路径错误: %s", r.URL.Path)
			}
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		}))
		cl, err := New(srv.URL, 9, testCred(t), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		r, err := cl.SubmitBatch(context.Background(), "sensor:cfg-1:0", batch())
		srv.Close()
		if gotAuth != "Machine mch_7."+fakeCredentialBody || gotKey != "sensor:cfg-1:0" {
			t.Fatalf("请求头错误: %q %q", gotAuth, gotKey)
		}
		if c.class == nil {
			if err != nil || r.TotalCount != 1 {
				t.Fatalf("HTTP %d 应视为已送达: %v %+v", c.status, err, r)
			}
			continue
		}
		var ue *Error
		if !errors.As(err, &ue) || ue.Class != *c.class {
			t.Fatalf("HTTP %d %s 分类错误: %v", c.status, c.body, err)
		}
		if strings.Contains(err.Error(), fakeCredentialBody) {
			t.Fatal("错误信息不得包含凭据")
		}
	}
}

func TestNetworkFailureIsRetryableAndRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/steal", http.StatusTemporaryRedirect)
	}))
	cl, _ := New(srv.URL, 9, testCred(t), 2*time.Second)
	_, err := cl.FetchConfig(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Status != http.StatusTemporaryRedirect || ue.Class != Fatal {
		t.Fatalf("重定向应作为错误返回且不跟随: %v", err)
	}
	srv.Close()
	_, err = cl.FetchConfig(context.Background())
	if !errors.As(err, &ue) || ue.Class != Retryable {
		t.Fatalf("连接失败应可重试: %v", err)
	}
}

func TestHealthWindowValidation(t *testing.T) {
	now := time.Now()
	good := HealthWindow{WindowStart: now, WindowEnd: now.Add(time.Minute), FlowsSeen: 10, FlowsEmitted: 6, FlowsDropped: 4}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, h := range []HealthWindow{
		{WindowStart: now, WindowEnd: now},
		{WindowStart: now, WindowEnd: now.Add(time.Minute), FlowsSeen: 1, FlowsEmitted: 2},
		{WindowStart: now, WindowEnd: now.Add(time.Minute), FlowsSeen: 10, FlowsEmitted: 6, FlowsDropped: 5},
		{WindowStart: now, WindowEnd: now.Add(time.Minute), Errors: map[string]int64{"bad key": 1}},
	} {
		if h.Validate() == nil {
			t.Fatalf("应拒绝: %+v", h)
		}
	}
}

func ptr(c Class) *Class { return &c }
