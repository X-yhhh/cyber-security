package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// validateManaged 保留短窗口入口；零时长只能由真实直接父进程托管，不向 lab/research 扩权。
func validateManaged(c config, duration time.Duration, parentPID, actualParent int, live bool) error {
	if parentPID == 0 {
		if duration == 0 {
			return fmt.Errorf("持续采集必须由后端托管")
		}
		return nil
	}
	if parentPID <= 1 || actualParent != parentPID || !live || duration != 0 ||
		c.Environment != "authorized" || c.CaptureScope != scopeAllInbound || c.Upload == nil ||
		!time.Now().Before(c.AuthorizedUntil) {
		return fmt.Errorf("后端托管采集范围或父进程无效")
	}
	return nil
}

// watchParent 同时覆盖正常退出和 SIGKILL 后的孤儿进程；PPID 改变后不等待上传网络恢复。
func watchParent(ctx context.Context, cancel context.CancelFunc, parentPID int, parent func() int) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if parent() != parentPID {
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// addressSourceInterface 表示本机地址不写死在配置里，而由托管方在每次启动时从采集接口读取。
const addressSourceInterface = "interface"

// interfaceAddresses 返回接口上与 ipv6 同地址族、可用于采集的单播地址；链路本地地址不算可用。
func interfaceAddresses(name string, ipv6 bool) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	raw, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range raw {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		addr := prefix.Addr().Unmap()
		if addr.Is6() == ipv6 && !addr.IsLinkLocalUnicast() && !addr.IsLoopback() && !addr.IsUnspecified() && !addr.IsMulticast() {
			out = append(out, addr.WithZone(""))
		}
	}
	return out, nil
}

func sameAddresses(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[netip.Addr]int{}
	for _, x := range a {
		seen[x.Unmap()]++
	}
	for _, x := range b {
		if seen[x.Unmap()]--; seen[x.Unmap()] < 0 {
			return false
		}
	}
	return true
}

// watchAddresses 在接口地址与本次会话登记的地址不一致时结束采集：BPF 过滤与方向判定都依赖本机地址，
// 地址变化后继续运行只会静默空采。退出后由后端托管方用新地址开启新会话（新 bootId）。
func watchAddresses(ctx context.Context, cancel context.CancelFunc, iface string, want []netip.Addr, every time.Duration,
	lookup func(string, bool) ([]netip.Addr, error), changed *atomic.Bool) {
	ipv6 := len(want) > 0 && want[0].Is6()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		current, err := lookup(iface, ipv6)
		if err != nil || !sameAddresses(current, want) {
			changed.Store(true)
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
