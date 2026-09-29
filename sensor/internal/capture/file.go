// Package capture 提供报文来源：pcap 文件（纯 Go，无 cgo）与实时网卡（libpcap/Npcap，见 live.go）。
package capture

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/xyh/cyber-security/sensor/internal/pipeline"
)

// ReadFile 把经典 pcap 文件逐帧送入流水线，结束时 Close。只接受以太网链路类型；
// 文件本身不被修改，也不会写出任何报文。
func ReadFile(path string, p *pipeline.Pipeline) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return fmt.Errorf("不是可读的 pcap 文件: %w", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		return fmt.Errorf("链路类型 %v 不是以太网", r.LinkType())
	}
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 pcap 失败: %w", err)
		}
		p.Frame(data, ci.Length, ci.Timestamp.UTC())
	}
	p.Close()
	return nil
}
