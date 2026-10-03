package hostguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// WalkPCAP 严格保留读取顺序，拒绝混接口/多 section。仅在完整读完后成功；回调可作受控标签旁路。
func WalkPCAP(path string, visit func([]byte, gopacket.CaptureInfo, uint64) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b := bufio.NewReaderSize(f, 1<<20)
	magic, err := b.Peek(4)
	if err != nil {
		return err
	}
	var r interface {
		ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}
	var ng *pcapgo.NgReader
	var link layers.LinkType
	multipleSections := false
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		op := pcapgo.DefaultNgReaderOptions
		op.WantMixedLinkType = true
		op.SectionEndCallback = func([]pcapgo.NgInterface, pcapgo.NgSectionInfo) { multipleSections = true }
		ng, err = pcapgo.NewNgReader(b, op)
		r = ng
	} else {
		var classic *pcapgo.Reader
		classic, err = pcapgo.NewReader(b)
		if err == nil {
			link = classic.LinkType()
			if !supportedLink(link) {
				return fmt.Errorf("不支持的链路类型")
			}
		}
		r = classic
	}
	if err != nil {
		return err
	}
	var seq uint64
	for {
		data, ci, readErr := r.ZeroCopyReadPacketData()
		if multipleSections || ng != nil && ng.NInterfaces() != 1 {
			return fmt.Errorf("v5 首版拒绝多捕获域 PCAPNG")
		}
		if ng != nil {
			iface, err := ng.Interface(0)
			if err != nil || !supportedLink(iface.LinkType) {
				return fmt.Errorf("不支持的接口类型")
			}
			link = iface.LinkType
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if ci.InterfaceIndex != 0 {
			return fmt.Errorf("跨接口报文")
		}
		seq++
		data, ci, err = normalizeLink(data, ci, link)
		if err != nil {
			return err
		}
		if err := visit(data, ci, seq); err != nil {
			return err
		}
	}
}

func supportedLink(link layers.LinkType) bool {
	return link == layers.LinkTypeEthernet || link == layers.LinkTypeRaw || link == layers.LinkType(12)
}

// RAW 的12/101编号都表示原始IP，补充的以太网头只作解析适配，IP长度和内容不变。
// 离线/现场必须走同一适配，不能将未知链路猜成以太网。
func normalizeLink(data []byte, ci gopacket.CaptureInfo, link layers.LinkType) ([]byte, gopacket.CaptureInfo, error) {
	if link == layers.LinkTypeEthernet {
		return data, ci, nil
	}
	if !supportedLink(link) || len(data) == 0 {
		return nil, ci, fmt.Errorf("RAW IP 帧无效")
	}
	b := make([]byte, 14+len(data))
	copy(b[14:], data)
	switch data[0] >> 4 {
	case 4:
		b[12] = 0x08
	case 6:
		b[12] = 0x86
		b[13] = 0xdd
	default:
		return nil, ci, fmt.Errorf("RAW IP 版本无效")
	}
	ci.Length += 14
	ci.CaptureLength += 14
	return b, ci, nil
}

func ReadPCAP(path string, e *Engine) error {
	if err := WalkPCAP(path, func(b []byte, ci gopacket.CaptureInfo, seq uint64) error {
		return e.Frame(b, ci.Length, ci.Timestamp, seq)
	}); err != nil {
		return err
	}
	return e.Close()
}

// LiveSource 的 Next 必须在100ms内返回，超时返回 ErrCaptureTimeout；实现不能保留载荷。
// Drops 的未知状态显式返回错误，触发 gap；时钟由 Now 注入以便与文件输入对拍。
type LiveSource interface {
	Next() ([]byte, gopacket.CaptureInfo, error)
	Drops() (uint64, error)
}

var ErrCaptureTimeout = errors.New("capture timeout")

// RunLive 接受已由调用方授权/打开的捕获句柄，不自行选择网卡或申请系统权限。
func RunLive(ctx context.Context, s LiveSource, e *Engine, now func() time.Time) error {
	if now == nil {
		return fmt.Errorf("实时输入缺少采集时钟")
	}
	e.emissionClock = now
	var seq, drops uint64
	known := false
	for ctx.Err() == nil {
		b, ci, err := s.Next()
		if err == nil {
			seq++
			if err = e.Frame(b, ci.Length, ci.Timestamp, seq); err != nil {
				return err
			}
		} else if errors.Is(err, io.EOF) {
			return e.Close()
		} else if !errors.Is(err, ErrCaptureTimeout) {
			_ = e.Gap(now())
			return err
		}
		at := now()
		n, err := s.Drops()
		if err != nil {
			known = false
			if err = e.Gap(at); err != nil {
				return err
			}
		} else {
			if !known && n > 0 || known && n != drops {
				if err = e.Gap(at); err != nil {
					return err
				}
			}
			drops = n
			known = true
		}
		if err = e.Tick(at); err != nil {
			return err
		}
	}
	return e.Close()
}
