// p1httpcanary 为 P1 授权良性任务提供固定内存文件；无磁盘服务、外联或防火墙操作。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

const fixtureBytes = 4 * 1024 * 1024

func private(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsLoopback() && (ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip))
}

// fixtureHandler 仅接受指定 peer 的 GET/HEAD，最多16次请求；Range 用于正常断点重试。
// 4 MiB 数据为公开确定性字节，服务不读取用户文件。网络层隔离仍须 runner 独立建立。
func fixtureHandler(peer netip.Addr, requests *atomic.Int64) http.Handler {
	data := make([]byte, fixtureBytes)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || remote.Addr().Unmap() != peer {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.URL.Path != "/fixture.bin" || (r.Method != "GET" && r.Method != "HEAD") {
			http.Error(w, "unsupported", 400)
			return
		}
		if requests.Add(1) > 16 {
			http.Error(w, "task budget exhausted", 429)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "fixture.bin", time.Unix(0, 0), bytes.NewReader(data))
	})
}

func run() error {
	self := flag.Bool("self-check", false, "只核验启动")
	listen := flag.String("listen", "", "本机私网 IPv4 高端口")
	peerText := flag.String("peer", "", "唯一授权 peer")
	duration := flag.Duration("duration", 120*time.Second, "1..180秒")
	flag.Parse()
	if *self {
		data := make([]byte, fixtureBytes)
		for i := range data {
			data[i] = byte(i % 251)
		}
		h := sha256.Sum256(data)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": "p1-http-canary-v1", "os": runtime.GOOS, "started": true, "fixtureBytes": fixtureBytes, "fixtureSha256": hex.EncodeToString(h[:])})
	}
	bind, e1 := netip.ParseAddrPort(*listen)
	peer, e2 := netip.ParseAddr(*peerText)
	if e1 != nil || e2 != nil || !private(bind.Addr()) || !private(peer) || peer == bind.Addr() || bind.Port() < 49152 || *duration < time.Second || *duration > 180*time.Second {
		return fmt.Errorf("授权地址、端口或期限无效")
	}
	// ListenTCP 只绑定指定本机地址；不使用通配地址，也不启动额外监听器。
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(bind))
	if err != nil {
		return err
	}
	defer listener.Close()
	var count atomic.Int64
	server := &http.Server{Handler: fixtureHandler(peer, &count), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	deadline := time.AfterFunc(*duration, func() { server.Close() })
	defer deadline.Stop()
	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	_ = server.Shutdown(context.Background())
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": "p1-http-canary-v1", "requests": count.Load(), "outboundConnectionsCreated": 0})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
