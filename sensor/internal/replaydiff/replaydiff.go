// Package replaydiff 逐字段比对 guardlive 1 倍速回放输出与 guardextract（research 离线提取）对同一文件的输出。
//
// research_pcap_replay：回放观察的 firstSeenAt/lastPacketAt/asOf/targetExpiresAt 减去运行摘要中的
// timeOffsetMicros 后还原为原事件时间；emittedAt 是真实墙钟，两侧都不参与比较。离线侧按回放所用的
// captureScope 做同一过滤。行为与原 cmd/guardreplaydiff 完全一致。
//
// lab_pcap_replay：同一 PCAP 在 lab 会话准入下回放，与 research 离线提取对拍。除 emittedAt 外，
// 只忽略已登记的 lab 差异字段（LabIgnoredFields；多场景串行 -lab-plan 另加 PlanIgnoredFields），
// 其余特征、上下文、质量标志、时间（统一减去同一固定偏移）和顺序必须逐字段一致。
// 离线侧 environment 必须为 research、回放侧必须为 lab，否则直接报错而不是静默忽略。
//
// 只读本地输入，不访问网络；不校验 peerKey 的映射正确性（需要私有密钥，由传感器准入负责）。
package replaydiff

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

// LabIgnoredFields 是 lab 与 research 之间登记的差异：环境标签、canary 映射后的 peerKey、
// 目标租约引用/期限以及来自上传心跳的 clockSkewMs。
var LabIgnoredFields = []string{"emittedAt", "environment", "peerKey", "targetRef", "targetExpiresAt", "quality.clockSkewMs"}

// PlanIgnoredFields 是多场景串行回放的额外登记差异：按 session/scenario 做 HMAC 命名空间的标识符。
var PlanIgnoredFields = []string{"observationId", "flowId", "parentConnectionId"}

type options struct {
	shift time.Duration
	lab   bool
	plan  bool
	env   string
}

func normalize(line []byte, o options) ([]byte, error) {
	var v hostguard.Observation
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	v.FirstSeenAt, v.LastPacketAt, v.AsOf = v.FirstSeenAt.Add(-o.shift).UTC(), v.LastPacketAt.Add(-o.shift).UTC(), v.AsOf.Add(-o.shift).UTC()
	if v.TargetExpiresAt != nil {
		t := v.TargetExpiresAt.Add(-o.shift).UTC()
		v.TargetExpiresAt = &t
	}
	v.EmittedAt = time.Time{}
	if o.lab {
		if v.Environment != o.env {
			return nil, fmt.Errorf("观察环境不是 %s", o.env)
		}
		v.Environment = ""
		v.PeerKey = ""
		v.TargetRef, v.TargetExpiresAt = nil, nil
		v.Quality.ClockSkewMs = nil
		if o.plan {
			v.ObservationID, v.FlowID, v.ParentConnectionID = "", "", ""
		}
	}
	return json.Marshal(v)
}

func diffFields(a, b []byte) []string {
	var x, y map[string]any
	json.Unmarshal(a, &x)
	json.Unmarshal(b, &y)
	var out []string
	for k := range x {
		ax, _ := json.Marshal(x[k])
		by, _ := json.Marshal(y[k])
		if !bytes.Equal(ax, by) {
			out = append(out, k)
		}
	}
	return out
}

type replayOffset struct {
	TimeOffsetMicros int64 `json:"timeOffsetMicros"`
}

// Compare 读取离线 JSONL、回放 JSONL 与回放运行摘要，返回去敏比较结果及是否逐字段一致。
// 摘要不是已完成的 research/lab pcap 回放或输入无法解析时返回错误。
func Compare(offline, replay io.Reader, report []byte) (map[string]any, bool, error) {
	var rep struct {
		Status       string         `json:"status"`
		Mode         string         `json:"mode"`
		CaptureScope string         `json:"captureScope"`
		Replay       *replayOffset  `json:"replay"`
		Replays      []replayOffset `json:"replays"`
	}
	if err := json.Unmarshal(report, &rep); err != nil || rep.Status != "completed" {
		return nil, false, fmt.Errorf("运行摘要不是已完成的 pcap 回放")
	}
	var offset int64
	left, right := options{}, options{}
	ignored := []string{"emittedAt"}
	switch {
	case rep.Mode == "research_pcap_replay" && rep.Replay != nil:
		offset = rep.Replay.TimeOffsetMicros
	case rep.Mode == "lab_pcap_replay" && rep.Replay != nil && len(rep.Replays) == 0:
		offset = rep.Replay.TimeOffsetMicros
		left, right = options{lab: true, env: "research"}, options{lab: true, env: "lab"}
		ignored = append([]string(nil), LabIgnoredFields...)
	case rep.Mode == "lab_pcap_replay" && rep.Replay == nil && len(rep.Replays) > 0:
		// 多场景共用登记的固定偏移；任一场景偏移不同说明不是同一会话时钟。
		offset = rep.Replays[0].TimeOffsetMicros
		for _, r := range rep.Replays {
			if r.TimeOffsetMicros != offset {
				return nil, false, fmt.Errorf("多场景回放的固定偏移不一致")
			}
		}
		left, right = options{lab: true, plan: true, env: "research"}, options{lab: true, plan: true, env: "lab"}
		ignored = append(append([]string(nil), LabIgnoredFields...), PlanIgnoredFields...)
	default:
		return nil, false, fmt.Errorf("运行摘要不是已完成的 pcap 回放")
	}
	right.shift = time.Duration(offset) * time.Microsecond
	so := bufio.NewScanner(offline)
	so.Buffer(make([]byte, 1<<20), 16<<20)
	sr := bufio.NewScanner(replay)
	sr.Buffer(make([]byte, 1<<20), 16<<20)
	ho, hr := sha256.New(), sha256.New()
	compared, skipped := 0, 0
	result := map[string]any{"captureScope": rep.CaptureScope, "timeOffsetMicros": offset, "ignoredFields": ignored}
	if left.lab {
		result["mode"] = rep.Mode
	}
	ok := true
	for {
		var want []byte
		for so.Scan() {
			line := so.Bytes()
			ho.Write(line)
			ho.Write([]byte{'\n'})
			var o hostguard.Observation
			if err := json.Unmarshal(line, &o); err != nil {
				return nil, false, err
			}
			if rep.CaptureScope == "all_inbound_tcp" && (o.Transport != "tcp" || o.Direction == "outbound") {
				skipped++
				continue
			}
			var err error
			if want, err = normalize(line, left); err != nil {
				return nil, false, err
			}
			break
		}
		if err := so.Err(); err != nil {
			return nil, false, err
		}
		var got []byte
		if sr.Scan() {
			hr.Write(sr.Bytes())
			hr.Write([]byte{'\n'})
			var err error
			if got, err = normalize(sr.Bytes(), right); err != nil {
				return nil, false, err
			}
		}
		if err := sr.Err(); err != nil {
			return nil, false, err
		}
		if want == nil && got == nil {
			break
		}
		if want == nil || got == nil {
			ok = false
			result["firstMismatch"] = map[string]any{"index": compared, "reason": "观察数量不一致"}
			break
		}
		if !bytes.Equal(want, got) {
			ok = false
			result["firstMismatch"] = map[string]any{"index": compared, "fields": diffFields(want, got)}
			break
		}
		compared++
	}
	result["compared"], result["offlineOutOfScope"], result["identical"] = compared, skipped, ok
	result["offlineSha256"], result["replaySha256"] = hex.EncodeToString(ho.Sum(nil)), hex.EncodeToString(hr.Sum(nil))
	return result, ok, nil
}
