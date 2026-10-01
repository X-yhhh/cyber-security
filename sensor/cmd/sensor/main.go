// Command sensor 是 unsw-nb15-flow-v4 软件传感器。
//
//	sensor run -config sensor.json            实时抓包并上报（接口须同时在本机白名单与后端批准配置中）
//	sensor extract -pcap in.pcap -out r.jsonl 离线把 pcap 构造为特征记录（不联网、不上报），用于 G2 对拍
//	sensor credential import|delete -config sensor.json   凭据经 stdin 写入/删除系统钥匙串，不回显
//	sensor version
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/agent"
	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/extract"
	"github.com/xyh/cyber-security/sensor/internal/keystore"
	"github.com/xyh/cyber-security/sensor/internal/privdrop"
	"github.com/xyh/cyber-security/sensor/internal/uplink"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("用法: sensor run|extract|credential|version"))
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "extract":
		err = runExtract(os.Args[2:])
	case "credential":
		err = credential(os.Args[2:])
	case "version":
		fmt.Println(agent.Version)
	default:
		err = fmt.Errorf("未知子命令 %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sensor:", err)
	os.Exit(1)
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "sensor.json", "本机配置文件")
	iface := fs.String("interface", "", "抓包接口（须同时在本机白名单与后端批准配置中）")
	duration := fs.Duration("duration", 0, "运行时长上限；0 表示直到收到终止信号")
	fs.Parse(args)
	if *duration < 0 {
		return errors.New("-duration 不能为负")
	}
	local, err := agent.LoadLocalConfig(*cfgPath)
	if err != nil {
		return err
	}
	// 抓包句柄需要特权。以 root 运行时只允许经 sudo 启动：打开句柄后立即降到 sudo 调用者，
	// 之后读取凭据、联网、写状态都以普通用户身份进行。普通用户直接运行时需已有 BPF 访问权限（access_bpf）。
	var target *privdrop.Target
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t, err := privdrop.FromSudo()
		if err != nil {
			return err
		}
		target = &t
	}
	h, err := capture.OpenLive(*iface, local.AllowedInterfaces)
	if err != nil {
		return err
	}
	defer h.Close()
	if target != nil {
		if err := privdrop.Drop(*target); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "sensor: 已打开 %s，并降权到 %s（uid %d），无法恢复 root\n", h.Interface, target.Name, target.UID)
	}
	cred, err := agent.LoadCredential(keystore.Default(), local)
	if err != nil {
		return fmt.Errorf("读取凭据失败: %w", err)
	}
	client, err := uplink.New(local.BaseURL, local.SensorID, cred, 15*time.Second)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	return agent.RunLive(ctx, local, client, bootID(), h)
}

// bootID 是本进程的随机记录键前缀，重启后记录键不会与上次重复。
func bootID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		fail(errors.New("无法生成随机启动标识"))
	}
	return "b" + hex.EncodeToString(b)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// runExtract 离线把 pcap 构造为特征记录 JSONL（不联网、不上报），实现见 internal/extract。
func runExtract(args []string) error {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	in := fs.String("pcap", "", "输入 pcap（以太网链路）")
	out := fs.String("out", "", "输出 JSONL")
	labelOut := fs.String("label-audit", "", "仅公开数据集离线标注：端点及头部推算长度 JSONL，不可作为模型输入")
	diagOut := fs.String("diagnostics", "", "可选：诊断计数 JSON 输出")
	keyBase := fs.String("key-base", "extract", "记录键前缀")
	mtu := fs.Int("mtu", 1500, "D11 超大包判定 MTU")
	var locals, subnets multi
	fs.Var(&locals, "local-addr", "本机地址（可重复）")
	fs.Var(&subnets, "subnet", "本机 IPv4 子网 CIDR（可重复，用于定向广播排除）")
	fs.Parse(args)
	if *in == "" || *out == "" || len(locals) == 0 {
		return errors.New("须提供 -pcap、-out 与至少一个 -local-addr")
	}
	var addrs []netip.Addr
	for _, s := range locals {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("本机地址无效: %s", s)
		}
		addrs = append(addrs, a.Unmap())
	}
	var prefixes []netip.Prefix
	for _, s := range subnets {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("子网无效: %s", s)
		}
		prefixes = append(prefixes, p)
	}
	if *labelOut != "" && (*labelOut == *out || *labelOut == *in || *labelOut == *diagOut) {
		return errors.New("标签旁路必须使用独立输出路径")
	}
	var auditFile *os.File
	if *labelOut != "" {
		var err error
		auditFile, err = os.OpenFile(*labelOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer auditFile.Close()
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	opt := extract.Options{LocalAddrs: addrs, Subnets: prefixes, KeyBase: *keyBase, MTU: *mtu}
	if auditFile != nil {
		opt.LabelAudit = auditFile
	}
	diag, runErr := extract.Run(*in, f, opt)
	if closeErr := f.Close(); runErr == nil {
		runErr = closeErr
	}
	if runErr != nil {
		return runErr
	}
	if *diagOut != "" {
		raw, err := extract.DiagnosticsJSON(diag)
		if err != nil {
			return err
		}
		return os.WriteFile(*diagOut, raw, 0o644)
	}
	return nil
}

func credential(args []string) error {
	if len(args) < 1 {
		return errors.New("用法: sensor credential import|delete -config sensor.json")
	}
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	cfgPath := fs.String("config", "sensor.json", "本机配置文件")
	fs.Parse(args[1:])
	local, err := agent.LoadLocalConfig(*cfgPath)
	if err != nil {
		return err
	}
	ks := keystore.Default()
	switch args[0] {
	case "import":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("未从 stdin 读到凭据")
		}
		cred, err := uplink.ParseCredential(strings.TrimSpace(line))
		if err != nil {
			return err
		}
		if err := ks.Put(local.KeystoreService, local.KeystoreAccount, cred.Literal()); err != nil {
			return err
		}
		fmt.Println("已写入钥匙串:", cred)
	case "delete":
		if err := ks.Delete(local.KeystoreService, local.KeystoreAccount); err != nil {
			return err
		}
		fmt.Println("已删除钥匙串条目")
	default:
		return fmt.Errorf("未知操作 %q", args[0])
	}
	return nil
}
