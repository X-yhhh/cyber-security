// Command pcapanon 把本机抓取的 pcap 假名化（规则见 internal/anon），供 G2 真实流量 fixtures 入库。
//
//	pcapanon -in raw.pcap -out anon.pcap -subnet 10.0.0.0/24 -local-v4 10.0.0.5 [-local-v6 ...]
//
// 只输出假名化后的本机地址与帧数，不打印原始地址或映射表。原始 pcap 由操作者在对拍后删除。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/xyh/cyber-security/sensor/internal/anon"
	"github.com/xyh/cyber-security/sensor/internal/spec"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pcapanon:", err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "", "原始 pcap（以太网链路）")
	out := flag.String("out", "", "输出的假名化 pcap")
	subnet := flag.String("subnet", "", "本机 IPv4 子网（/24）")
	localV4 := flag.String("local-v4", "", "本机 IPv4 地址（须在子网内）")
	start := flag.String("start", "2026-10-01T00:00:00Z", "输出首帧的整秒时间（RFC 3339）")
	keep := flag.Duration("keep", 0, "只保留首帧之后这段时长内的帧；0 表示全部")
	var localV6 multi
	flag.Var(&localV6, "local-v6", "本机 IPv6 地址（可重复）")
	flag.Parse()
	if *in == "" || *out == "" || *in == *out {
		return errors.New("须提供不同的 -in 与 -out")
	}
	sub, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return errors.New("-subnet 无效")
	}
	l4, err := netip.ParseAddr(*localV4)
	if err != nil || !sub.Contains(l4) {
		return errors.New("-local-v4 无效或不在子网内")
	}
	st, err := time.Parse(time.RFC3339, *start)
	if err != nil || st.Truncate(time.Second) != st {
		return errors.New("-start 须为整秒 RFC 3339 时间")
	}
	var l6 []netip.Addr
	for _, s := range localV6 {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return errors.New("-local-v6 无效")
		}
		l6 = append(l6, a)
	}
	a, err := anon.New(anon.Options{Subnet: sub.Masked(), LocalV6: l6, Start: st.UTC()})
	if err != nil {
		return err
	}
	src, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer src.Close()
	r, err := pcapgo.NewReader(src)
	if err != nil {
		return fmt.Errorf("不是可读的 pcap: %w", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		return errors.New("链路类型不是以太网")
	}
	dst, err := os.Create(*out)
	if err != nil {
		return err
	}
	w := pcapgo.NewWriter(dst)
	if err := w.WriteFileHeader(uint32(spec.SnapLen), layers.LinkTypeEthernet); err != nil {
		dst.Close()
		return err
	}
	n := 0
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			dst.Close()
			return fmt.Errorf("读取失败: %w", err)
		}
		d, ts := a.Rewrite(data, ci.Length, ci.Timestamp.UTC())
		if *keep > 0 && ts.Sub(st) >= *keep {
			break
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(d), Length: ci.Length}, d); err != nil {
			dst.Close()
			return err
		}
		n++
	}
	if err := dst.Close(); err != nil {
		return err
	}
	fmt.Printf("frames=%d local_v4=%s", n, a.Map(l4))
	for _, l := range l6 {
		fmt.Printf(" local_v6=%s", a.Map(l))
	}
	fmt.Println(" subnet=192.0.2.0/24")
	return nil
}
