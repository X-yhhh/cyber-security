package hostguard

import (
	"bufio"
	"context"
	"encoding/binary"
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
	return link == layers.LinkTypeEthernet || link == layers.LinkTypeRaw || link == layers.LinkType(12) || link == layers.LinkTypeNull || link == layers.LinkTypeLoop
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
	if link == layers.LinkTypeNull || link == layers.LinkTypeLoop {
		if len(data) < 5 || ci.Length < 5 || ci.CaptureLength < 5 {
			return nil, ci, fmt.Errorf("回环 AF 头截断")
		}
		// DLT_NULL 使用捕获平台本机字节序；兼容已知 AF 的两种字节序。
		// DLT_LOOP 固定网络字节序。只接受有定义的 IPv4/IPv6 AF 且核对 IP 版本。
		af := binary.BigEndian.Uint32(data[:4])
		if link == layers.LinkTypeNull && !loopAF(af, data[4]>>4) {
			af = binary.LittleEndian.Uint32(data[:4])
		}
		if !loopAF(af, data[4]>>4) {
			return nil, ci, fmt.Errorf("未知或不匹配的回环 AF")
		}
		data = data[4:]
		ci.Length -= 4
		ci.CaptureLength -= 4
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

func loopAF(af uint32, version byte) bool {
	return af == 2 && version == 4 || (af == 10 || af == 24 || af == 28 || af == 30) && version == 6
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
	return RunLiveTrace(ctx, s, e, now, nil)
}

// RunLiveTrace 将同一捕获句柄的头部事件、真实 drop/gap 与 Tick 顺序送到私有旁路。
// 不记录载荷；旁路写入失败即停止本次采集，不能交付不可复算的成功报告。
func RunLiveTrace(ctx context.Context, s LiveSource, e *Engine, now func() time.Time, trace func(LiveEvent) error) error {
	return RunLiveObserved(ctx, s, e, now, trace, nil)
}

// LiveSample 是一次轮询后的累计捕获计数，只供独立健康观察器使用；不含报文、端点或特征。
// DropsKnown=false 表示内核丢包不可测，不能当作 0；Gap 表示本轮出现了丢包变化、计数未知或读取错误。
type LiveSample struct {
	At            time.Time
	PacketsSeen   uint64
	Drops         uint64
	DropsKnown    bool
	Gap           bool
	CapacityDrops int64
	LateCount     int64
}

// CaptureCounters 返回引擎内累计的容量丢弃和迟到包数；调用方须与引擎在同一 goroutine。
func (e *Engine) CaptureCounters() (capacityDrops, late int64) {
	return e.Stats["buffer_drops"] + e.Stats["flow_drops"] + e.Stats["connection_drops"] + e.Stats["context_drops"], e.Stats["late_packets"]
}

// RunLiveObserved 在 RunLiveTrace 基础上，于每轮轮询后同步回调 observe（可为 nil）。
// 回调与引擎同一 goroutine，只读计数；返回错误立即停止，不允许健康上报失败后继续采集。
// 有观察器时在首包前建立基线，退出时重新读取计数并包含 Close 的容量变化；空闲超时也持续采样。
func RunLiveObserved(ctx context.Context, s LiveSource, e *Engine, now func() time.Time, trace func(LiveEvent) error, observe func(LiveSample) error) (runErr error) {
	if now == nil {
		return fmt.Errorf("实时输入缺少采集时钟")
	}
	var seq, drops uint64
	known := false
	apply := func(v LiveEvent) error {
		if trace != nil {
			if err := trace(v); err != nil {
				return err
			}
		}
		return e.ApplyLiveEvent(v)
	}
	observeFailed := false
	sample := func(at time.Time, gap bool) error {
		if observe != nil {
			capacity, late := e.CaptureCounters()
			if err := observe(LiveSample{At: at, PacketsSeen: seq, Drops: drops, DropsKnown: known, Gap: gap, CapacityDrops: capacity, LateCount: late}); err != nil {
				observeFailed = true
				return err
			}
		}
		return nil
	}
	readDrops := func() bool {
		n, err := s.Drops()
		if err != nil {
			known = false
			return true
		}
		gap := !known && n > 0 || known && n != drops
		drops, known = n, true
		return gap
	}
	if observe != nil {
		// 句柄仍由调用方持有；结束采样必须在 Close 句柄之前完成。
		defer func() {
			if !observeFailed {
				gap := readDrops()
				runErr = errors.Join(runErr, sample(now(), gap || runErr != nil))
			}
		}()
		gap := readDrops()
		at := now()
		if gap {
			if err := apply(LiveEvent{Kind: "gap", At: at, DropsKnown: known, Drops: drops}); err != nil {
				return err
			}
		}
		if err := sample(at, gap); err != nil {
			return err
		}
	}
	for ctx.Err() == nil {
		b, ci, err := s.Next()
		at := now()
		if err == nil {
			seq++
			p, status := Parse(b, ci.Length, ci.Timestamp, seq, e.cfg.MTU)
			if err = apply(LiveEvent{Kind: "frame", At: at, Packet: &p, ParseStatus: status}); err != nil {
				return err
			}
		} else if errors.Is(err, io.EOF) {
			return apply(LiveEvent{Kind: "close", At: at})
		} else if !errors.Is(err, ErrCaptureTimeout) {
			if gapErr := apply(LiveEvent{Kind: "gap", At: at}); gapErr != nil {
				return errors.Join(err, gapErr)
			}
			return err
		}
		gap := readDrops()
		if gap {
			if err = apply(LiveEvent{Kind: "gap", At: at, DropsKnown: known, Drops: drops}); err != nil {
				return err
			}
		}
		if err = apply(LiveEvent{Kind: "tick", At: at, DropsKnown: known, Drops: drops}); err != nil {
			return err
		}
		if err = sample(at, gap); err != nil {
			return err
		}
	}
	at := now()
	return apply(LiveEvent{Kind: "close", At: at})
}

// LiveEvent 是私有、仅含头部的同包复算格式；包含端点，禁止提交或上传。
type LiveEvent struct {
	Kind        string    `json:"kind"`
	At          time.Time `json:"at"`
	Packet      *Packet   `json:"packet,omitempty"`
	ParseStatus string    `json:"parseStatus,omitempty"`
	DropsKnown  bool      `json:"dropsKnown"`
	Drops       uint64    `json:"drops"`
}

// ApplyLiveEvent 只复算冻结捕获轨迹，不开抓包句柄；close 沿用原捕获的截止点。
func (e *Engine) ApplyLiveEvent(v LiveEvent) error {
	if v.At.IsZero() {
		return fmt.Errorf("轨迹缺少采集时刻")
	}
	e.emissionClock = func() time.Time { return v.At }
	switch v.Kind {
	case "frame":
		if v.Packet == nil || v.ParseStatus == "" {
			return fmt.Errorf("轨迹缺少头部")
		}
		return e.frameParsed(*v.Packet, v.ParseStatus)
	case "gap":
		return e.Gap(v.At)
	case "tick":
		return e.Tick(v.At)
	case "close":
		return e.Close()
	default:
		return fmt.Errorf("未知轨迹事件")
	}
}
