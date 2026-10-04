package main

import (
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestPeerBudgetAndRange(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.1")
	var count atomic.Int64
	handler := fixtureHandler(peer, &count)
	request := httptest.NewRequest("GET", "http://canary/fixture.bin", nil)
	request.RemoteAddr = "192.0.2.2:51000"
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != 403 || count.Load() != 0 {
		t.Fatal("未知 peer 必须拒绝且不消耗任务预算")
	}
	request.RemoteAddr = "192.0.2.1:51000"
	request.Header.Set("Range", "bytes=1048576-1049599")
	rangeResult := httptest.NewRecorder()
	handler.ServeHTTP(rangeResult, request)
	if rangeResult.Code != 206 || rangeResult.Body.Len() != 1024 || rangeResult.Body.Bytes()[0] != byte(1048576%251) {
		t.Fatal("正常断点恢复必须返回准确字节")
	}
	count.Store(16)
	exhausted := httptest.NewRecorder()
	handler.ServeHTTP(exhausted, request)
	if exhausted.Code != 429 {
		t.Fatal("必须拒绝超预算请求")
	}
}
