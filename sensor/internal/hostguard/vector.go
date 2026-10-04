package hostguard

import (
	"fmt"
	"math"
)

// Vector 是模型边界的未拟合输入：类别仍为显式词汇，后续只可用 train 词表编码。
// 无 ID、地址、端口、绝对时间、标签或 closeReason；结构性 null 才使用 value=0/mask=1。
type Vector struct {
	Values     [43]float32 `json:"numeric_values"`
	Missing    [43]float32 `json:"numeric_missing"`
	Categories [3]string   `json:"categorical_values"`
}

// NumericOrder 与冻结 feature-profile 顺序一一对应；契约验证器必须核对该顺序。
var NumericOrder = []string{
	"features.elapsedMs", "features.bytesOutbound", "features.bytesInbound", "features.packetsOutbound", "features.packetsInbound",
	"features.lengthMin", "features.lengthMax", "features.lengthMean", "features.lengthStd", "features.iatMeanUs", "features.iatStdUs",
	"features.synCount", "features.synAckCount", "features.rstCount", "features.finCount", "features.handshakeSeen",
}

func init() {
	for _, w := range []int{1, 5, 30} {
		for _, n := range []string{"coverageMs", "peerFlowStarts", "peerSynCount", "peerRstCount", "peerDistinctServicePorts", "hostFlowStarts", "hostDistinctPeers", "peerBytesOutbound", "peerBytesInbound"} {
			NumericOrder = append(NumericOrder, fmt.Sprintf("contexts.%d.%s", w, n))
		}
	}
}

func ModelVector(o Observation) (Vector, error) {
	v := Vector{Categories: [3]string{o.Transport, o.Direction, o.ServiceClass}}
	f := o.Features
	if o.ContractVersion != Version || len(o.Contexts) != 3 || o.AsOf.Before(o.LastPacketAt) || o.LastPacketAt.Before(o.FirstSeenAt) || o.EmittedAt.Before(o.AsOf) || f.PacketsOutbound+f.PacketsInbound < 1 {
		return v, fmt.Errorf("观察不满足时间/结构契约")
	}
	if f.ElapsedMs != float64(o.AsOf.Sub(o.FirstSeenAt))/1e6 {
		return v, fmt.Errorf("elapsedMs 不一致")
	}
	x := []float64{f.ElapsedMs, float64(f.BytesOutbound), float64(f.BytesInbound), float64(f.PacketsOutbound), float64(f.PacketsInbound), float64(f.LengthMin), float64(f.LengthMax), f.LengthMean, f.LengthStd}
	for _, p := range []*float64{f.IATMeanUs, f.IATStdUs} {
		if p == nil {
			v.Missing[len(x)] = 1
			x = append(x, 0)
		} else {
			x = append(x, *p)
		}
	}
	for _, p := range []*int64{f.SynCount, f.SynAckCount, f.RstCount, f.FinCount} {
		if p == nil {
			v.Missing[len(x)] = 1
			x = append(x, 0)
		} else {
			x = append(x, float64(*p))
		}
	}
	if f.HandshakeSeen == nil {
		v.Missing[len(x)] = 1
		x = append(x, 0)
	} else if *f.HandshakeSeen {
		x = append(x, 1)
	} else {
		x = append(x, 0)
	}
	for i, w := range []int{1, 5, 30} {
		c := o.Contexts[i]
		if c.WindowSeconds != w || c.CoverageMs > float64(w*1000) {
			return v, fmt.Errorf("上下文顺序/覆盖非法")
		}
		x = append(x, c.CoverageMs, float64(c.PeerFlowStarts), float64(c.PeerSynCount), float64(c.PeerRstCount), float64(c.PeerDistinctServicePorts), float64(c.HostFlowStarts), float64(c.HostDistinctPeers), float64(c.PeerBytesOutbound), float64(c.PeerBytesInbound))
	}
	for i, n := range x {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > math.MaxFloat32 {
			return v, fmt.Errorf("数值不可安全编码")
		}
		v.Values[i] = float32(n)
	}
	return v, nil
}
