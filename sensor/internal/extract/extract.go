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
	// LabelAudit 只用于公开数据集离线标注；nil 保持既有无地址输出。
	LabelAudit io.Writer
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
	tab := flow.NewTable(opt.MTU, 1_000_000)
	if opt.LabelAudit != nil {
		tab.EnableLabelAudit()
	}
	policy := feature.NewAddressPolicy(opt.LocalAddrs, opt.Subnets)
	p := pipeline.New(tab,
		feature.NewBuilder(policy, opt.KeyBase),
		func(rs []feature.Record) {
			for _, r := range rs {
				if werr == nil {
					werr = enc.Encode(Line{r.RecordKey, r.ExportSeq, r.FlowStartAt.UTC(), r.FlowEndAt.UTC(),
						r.Status, r.Reason, r.CloseReason, r.AF, r.Viewpoint, r.HandshakeSeen, r.Features})
				}
			}
		})
	var auditWriter *bufio.Writer
	if opt.LabelAudit != nil {
		auditWriter = bufio.NewWriter(opt.LabelAudit)
		auditEncoder := json.NewEncoder(auditWriter)
		p.CompletedObserver = func(c flow.Completed) {
			if werr == nil {
				werr = auditEncoder.Encode(LabelLine{c.ExportSeq, c.Start.UTC(), c.Last.UTC(), c.Init.Addr.String(), c.Resp.Addr.String(), c.Init.Port, c.Resp.Port, c.Key.Proto, c.Segment, c.Reason, c.LabelAudit,
					policy.Classify(c.Init.Addr, c.Resp.Addr).Excluded})
			}
		}
	}
	if err := capture.ReadFile(pcapPath, p); err != nil {
		return pipeline.Diagnostics{}, err
	}
	if werr != nil {
		return pipeline.Diagnostics{}, werr
	}
	if auditWriter != nil {
		if err := auditWriter.Flush(); err != nil {
			return p.Diagnostics(), err
		}
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

// LabelLine 是只在离线标注文件中保存的头部元数据，不能作为模型输入或上报字段。
type LabelLine struct {
	ExportSeq     int64            `json:"exportSeq"`
	Start         time.Time        `json:"flowStartAt"`
	End           time.Time        `json:"flowEndAt"`
	Initiator     string           `json:"initiator"`
	Responder     string           `json:"responder"`
	InitiatorPort uint16           `json:"initiatorPort"`
	ResponderPort uint16           `json:"responderPort"`
	Protocol      uint8            `json:"protocol"`
	Segment       int              `json:"segment"`
	CloseReason   string           `json:"closeReason"`
	Lengths       *flow.LabelAudit `json:"lengths"`
	// 排除决定复用生产地址策略，使未入窗流也可逐条审查，不另造过滤规则。
	ExcludedReason string `json:"excludedReason,omitempty"`
}
