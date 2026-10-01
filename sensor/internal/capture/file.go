// Package capture 提供报文来源：pcap 文件（纯 Go，无 cgo）与实时网卡（libpcap/Npcap，见 live.go）。
package capture

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/xyh/cyber-security/sensor/internal/pipeline"
)

// ReadFile 自动识别经典 pcap 与 pcapng，逐帧送入同一流水线，结束时 Close。只接受以太网链路类型；
// 文件本身不被修改，也不会写出任何报文。
func ReadFile(path string, p *pipeline.Pipeline) error {
	if err := WalkFile(path, func(data []byte, ci gopacket.CaptureInfo) error {
		p.Frame(data, ci.Length, ci.Timestamp.UTC())
		return nil
	}); err != nil {
		return err
	}
	p.Close()
	return nil
}

// WalkFile 逐包只读遍历，同时校验全部 section 的接口（包括没有报文的接口）。回调错误立即终止。
func WalkFile(path string, visit func([]byte, gopacket.CaptureInfo) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buffer := bufio.NewReader(f)
	magic, err := buffer.Peek(4)
	if err != nil {
		return fmt.Errorf("读取抓包文件头失败: %w", err)
	}
	var r interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
		LinkType() layers.LinkType
	}
	var interfaceErr error
	checkInterfaces := func(ifaces []pcapgo.NgInterface, _ pcapgo.NgSectionInfo) {
		for _, iface := range ifaces {
			if iface.LinkType != layers.LinkTypeEthernet {
				interfaceErr = fmt.Errorf("pcapng 含非以太网接口 %v", iface.LinkType)
			}
		}
	}
	isNg := string(magic) == "\x0a\x0d\x0d\x0a"
	if isNg {
		// 按每包接口检查，覆盖跨 section 的接口变化；默认选项可能静默跳过不同链路的包。
		options := pcapgo.DefaultNgReaderOptions
		options.WantMixedLinkType = true
		options.SectionEndCallback = checkInterfaces
		r, err = pcapgo.NewNgReader(buffer, options)
	} else {
		r, err = pcapgo.NewReader(buffer)
	}
	if err != nil {
		return fmt.Errorf("不是可读的 pcap 文件: %w", err)
	}
	if !isNg && r.LinkType() != layers.LinkTypeEthernet {
		return fmt.Errorf("链路类型 %v 不是以太网", r.LinkType())
	}
	for {
		data, ci, err := r.ReadPacketData()
		if interfaceErr != nil {
			return interfaceErr
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 pcap 失败: %w", err)
		}
		if isNg {
			if len(ci.AncillaryData) == 0 || ci.AncillaryData[0] != layers.LinkTypeEthernet {
				return fmt.Errorf("pcapng 接口 %d 不是以太网", ci.InterfaceIndex)
			}
		}
		if err := visit(data, ci); err != nil {
			return err
		}
	}
	if ng, ok := r.(*pcapgo.NgReader); ok {
		for i := 0; i < ng.NInterfaces(); i++ {
			iface, err := ng.Interface(i)
			if err != nil {
				return err
			}
			checkInterfaces([]pcapgo.NgInterface{iface}, pcapgo.NgSectionInfo{})
		}
	}
	return interfaceErr
}
