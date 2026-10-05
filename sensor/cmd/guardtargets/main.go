// guardtargets 将 P2 本机目标注册表作为独立 mTLS 服务运行，不持有防火墙权限。
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type configuration struct {
	Listen          string                `json:"listen"`
	CertificateFile string                `json:"certificateFile"`
	KeyFile         string                `json:"keyFile"`
	CAFile          string                `json:"caFile"`
	AuthorizedUntil time.Time             `json:"authorizedUntil"`
	Scope           hostguard.TargetScope `json:"scope"`
}

// run 仅绑定明确的回环地址，强制独立 collector/executor 证书及整体运行期限。
// 身份或本机地址改变后须重新启动；停机主动销毁所有易失 targetRef。
func run(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	var c configuration
	if err = decoder.Decode(&c); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("CONFIG_INVALID")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !time.Now().Before(c.AuthorizedUntil) {
		return errors.New("LOCAL_AUTHORIZED_SCOPE_REQUIRED")
	}
	cert, err := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if err != nil {
		return err
	}
	roots, err := os.ReadFile(c.CAFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return errors.New("CA_INVALID")
	}
	registry, err := hostguard.NewTargetRegistry(c.Scope, time.Now)
	if err != nil {
		return err
	}
	defer registry.Invalidate()
	server := &http.Server{Addr: c.Listen, Handler: registry, TLSConfig: hostguard.TargetTLS(cert, pool),
		ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, c.AuthorizedUntil)
	defer cancel()
	go func() {
		<-ctx.Done()
		registry.Invalidate()
		_ = server.Close()
	}()
	err = server.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	path := flag.String("config", "", "受控本机配置绝对路径")
	flag.Parse()
	if *path == "" || run(*path) != nil {
		fmt.Fprintln(os.Stderr, "TARGET_SERVICE_CONFIGURATION_OR_RUNTIME_FAILED")
		os.Exit(1)
	}
}
