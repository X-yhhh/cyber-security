// Package extract 离线把 pcap 构造为特征记录 JSONL（不联网、不上报）。
//
// `sensor extract` 与 G2 fixtures 生成器共用本实现：提交到后端测试资源的期望记录，
// 就是当前 Go 实现对同一 pcap 的输出（G2 跨语言对拍的 Go 侧）。
package extract

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/capture"
	"github.com/xyh/cyber-security/sensor/internal/feature"
	"github.com/xyh/cyber-security/sensor/internal/flow"
	"github.com/xyh/cyber-security/sensor/internal/pipeline"
)

// Options 是离线提取参数。
type Options struct {
	LocalAddrs []netip.Addr
	Subnets    []netip.Prefix
	KeyBase    string
	MTU        int
}

// Line 是输出的一行：状态、元数据与（ready 时）按契约顺序的特征。地址不输出。
type Line struct {
	RecordKey     string            `json:"recordKey"`
	ExportSeq     int64             `json:"exportSeq"`
	FlowStartAt   time.Time         `json:"flowStartAt"`
	FlowEndAt     time.Time         `json:"flowEndAt"`
	Status        string            `json:"status"`
	Reason        string            `json:"reason,omitempty"`
	CloseReason   string            `json:"closeReason"`
	AddressFamily string            `json:"addressFamily"`
	Viewpoint     string            `json:"viewpoint"`
	HandshakeSeen bool              `json:"handshakeSeen"`
	Features      *feature.Features `json:"features"`
}

// Run 读取 pcap，把全部记录（含非 ready）按释放顺序写到 out，返回诊断计数。
func Run(pcapPath string, out io.Writer, opt Options) (pipeline.Diagnostics, error) {
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	var werr error
	p := pipeline.New(flow.NewTable(opt.MTU, 1_000_000),
		feature.NewBuilder(feature.NewAddressPolicy(opt.LocalAddrs, opt.Subnets), opt.KeyBase),
		func(rs []feature.Record) {
			for _, r := range rs {
				if werr == nil {
					werr = enc.Encode(Line{r.RecordKey, r.ExportSeq, r.FlowStartAt.UTC(), r.FlowEndAt.UTC(),
						r.Status, r.Reason, r.CloseReason, r.AF, r.Viewpoint, r.HandshakeSeen, r.Features})
				}
			}
		})
	if err := capture.ReadFile(pcapPath, p); err != nil {
		return pipeline.Diagnostics{}, err
	}
	if werr != nil {
		return pipeline.Diagnostics{}, werr
	}
	return p.Diagnostics(), w.Flush()
}

// DiagnosticsJSON 以固定格式序列化诊断计数（map 键由 encoding/json 排序，输出确定）。
func DiagnosticsJSON(d pipeline.Diagnostics) ([]byte, error) {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
