// p1canary 仅提供有界 TCP 回显，用于授权测试；不发起连接，不抓包，不操作防火墙。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const greeting = "host-guard-p1-canary\n"

func allowedIP(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsLoopback() && (ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip))
}

// serve 只绑定一个本机 IPv4 高端口，并只接受指定测试 peer；网络层隔离仍须由 runner 独立证明。
func serve(listen string, peer netip.Addr, duration time.Duration) error {
	bind, err := netip.ParseAddrPort(listen)
	if err != nil || !allowedIP(bind.Addr()) || bind.Port() < 49152 || !allowedIP(peer) || peer == bind.Addr() || duration < time.Second || duration > 3*time.Minute {
		return fmt.Errorf("须使用独立私网/覆盖网 IPv4、本机高端口、测试 peer 和 1..180 秒期限")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	local := false
	for _, addr := range addrs {
		if prefix, e := netip.ParsePrefix(addr.String()); e == nil && prefix.Addr().Unmap() == bind.Addr() {
			local = true
		}
	}
	if !local {
		return fmt.Errorf("监听地址不属于本机")
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(bind))
	if err != nil {
		return err
	}
	defer listener.Close()
	deadline := time.Now().Add(duration)
	if err = listener.SetDeadline(deadline); err != nil {
		return err
	}
	var active, accepted, rejected atomic.Int64
	var workers sync.WaitGroup
	for {
		conn, e := listener.AcceptTCP()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				break
			}
			return e
		}
		remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		if remote != peer || active.Load() >= 8 {
			rejected.Add(1)
			conn.Close()
			continue
		}
		accepted.Add(1)
		active.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer active.Add(-1)
			defer conn.Close()
			conn.SetDeadline(deadline)
			buf := make([]byte, len(greeting))
			for {
				if _, e := io.ReadFull(conn, buf); e != nil {
					return
				}
				if string(buf) != greeting {
					return
				}
				if _, e := io.WriteString(conn, greeting); e != nil {
					return
				}
			}
		}()
	}
	workers.Wait()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": "p1-canary-v1", "accepted": accepted.Load(), "rejected": rejected.Load(), "outboundConnectionsCreated": 0})
}

func run() error {
	self := flag.Bool("self-check", false, "只证明程序实际启动，不监听或改系统")
	listen := flag.String("listen", "", "专用本机 IPv4:高端口")
	peer := flag.String("peer", "", "唯一测试 peer IPv4")
	duration := flag.Duration("duration", 90*time.Second, "最多三分钟")
	flag.Parse()
	if *self {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": "p1-canary-v1", "os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "started": true, "firewallModified": false, "captureStarted": false})
	}
	ip, err := netip.ParseAddr(*peer)
	if err != nil {
		return fmt.Errorf("peer 无效")
	}
	return serve(*listen, ip.Unmap(), *duration)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
