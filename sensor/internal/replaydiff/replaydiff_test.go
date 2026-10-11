package replaydiff

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

var source = time.Date(2020, 1, 1, 0, 0, 0, 123000, time.UTC)

func observation(env string, shift time.Duration) hostguard.Observation {
	port := uint16(443)
	iat := 12.5
	at := source.Add(shift)
	return hostguard.Observation{ContractVersion: hostguard.Version, ObservationID: "dfc49b85-02a0-4bb5-beca-83224aec080a", AssetID: "00000000-0000-4000-8000-000000000002",
		SensorID: "00000000-0000-4000-8000-000000000003", BootID: "00000000-0000-4000-8000-000000000004", CaptureScopeID: "00000000-0000-4000-8000-000000000005",
		FlowID: "00000000-0000-4000-8000-000000000006", ParentConnectionID: "00000000-0000-4000-8000-000000000007", Profile: "prefix", Environment: env,
		FirstSeenAt: at.Add(-time.Second), LastPacketAt: at, AsOf: at, EmittedAt: time.Now().UTC(), AddressFamily: "ipv4", Transport: "tcp", Direction: "inbound",
		ServiceClass: "https", ServicePort: &port, PeerKey: "original", KeyEpoch: 1,
		Features: hostguard.Features{ElapsedMs: 1000, BytesInbound: 42, PacketsInbound: 2, IATMeanUs: &iat}, Contexts: []hostguard.Context{{WindowSeconds: 5, PeerFlowStarts: 1}}}
}

// lab 回放侧：只改登记差异字段，并整体平移固定偏移。
func labView(o hostguard.Observation) hostguard.Observation {
	ref := "00000000-0000-4000-8000-0000000000aa"
	expires := o.LastPacketAt.Add(15 * time.Second)
	skew := 3.0
	o.Environment = "lab"
	o.PeerKey = "canary"
	o.TargetRef, o.TargetExpiresAt = &ref, &expires
	o.Quality.ClockSkewMs = &skew
	return o
}

func jsonl(t *testing.T, rows ...hostguard.Observation) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	for _, r := range rows {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	return bytes.NewReader(b.Bytes())
}

func report(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResearchModeUnchanged(t *testing.T) {
	shift := 7 * time.Second
	rep := report(t, map[string]any{"status": "completed", "mode": "research_pcap_replay", "captureScope": "service", "replay": map[string]any{"timeOffsetMicros": shift.Microseconds()}})
	result, ok, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, observation("research", shift)), rep)
	if err != nil || !ok || !slices.Equal(result["ignoredFields"].([]string), []string{"emittedAt"}) || result["mode"] != nil {
		t.Fatalf("research 对拍改变: %v %v %v", result, ok, err)
	}
	// research 模式不忽略 lab 登记差异。
	other := observation("research", shift)
	other.PeerKey = "canary"
	if _, ok, err = Compare(jsonl(t, observation("research", 0)), jsonl(t, other), rep); err != nil || ok {
		t.Fatal("research 模式忽略了 peerKey 差异")
	}
}

func TestLabModeIgnoresOnlyRegisteredFields(t *testing.T) {
	shift := 1000 * time.Hour
	single := report(t, map[string]any{"status": "completed", "mode": "lab_pcap_replay", "captureScope": "service", "replay": map[string]any{"timeOffsetMicros": shift.Microseconds()}})
	result, ok, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, labView(observation("research", shift))), single)
	if err != nil || !ok || !slices.Equal(result["ignoredFields"].([]string), LabIgnoredFields) || result["compared"] != 1 {
		t.Fatalf("lab 对拍失败: %v %v %v", result, ok, err)
	}
	for name, change := range map[string]func(*hostguard.Observation){
		"feature": func(o *hostguard.Observation) { o.Features.BytesInbound++ },
		"context": func(o *hostguard.Observation) { o.Contexts[0].PeerFlowStarts++ },
		"time":    func(o *hostguard.Observation) { o.AsOf = o.AsOf.Add(time.Microsecond) },
		"quality": func(o *hostguard.Observation) { o.Quality.LatePacket = true },
		"id":      func(o *hostguard.Observation) { o.FlowID = "00000000-0000-4000-8000-0000000000ff" },
	} {
		bad := labView(observation("research", shift))
		change(&bad)
		if _, ok, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, bad), single); err != nil || ok {
			t.Fatalf("%s 差异被忽略", name)
		}
	}
	extra := labView(observation("research", shift))
	if _, ok, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, extra, extra), single); err != nil || ok {
		t.Fatal("观察数量差异被忽略")
	}
	// 环境标签必须真实是 research 对 lab，不能拿两份 lab 或两份 research 冒充。
	if _, _, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, observation("research", shift)), single); err == nil {
		t.Fatal("回放侧不是 lab 仍被接受")
	}
	if _, _, err := Compare(jsonl(t, labView(observation("research", 0))), jsonl(t, labView(observation("research", shift))), single); err == nil {
		t.Fatal("离线侧不是 research 仍被接受")
	}
}

func TestLabPlanSharesOneFixedOffset(t *testing.T) {
	shift := time.Hour
	replays := []map[string]any{{"timeOffsetMicros": shift.Microseconds()}, {"timeOffsetMicros": shift.Microseconds()}}
	plan := report(t, map[string]any{"status": "completed", "mode": "lab_pcap_replay", "captureScope": "service", "replays": replays})
	got := labView(observation("research", shift))
	got.ObservationID, got.FlowID, got.ParentConnectionID = "00000000-0000-4000-8000-0000000000b1", "00000000-0000-4000-8000-0000000000b2", "00000000-0000-4000-8000-0000000000b3"
	result, ok, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, got), plan)
	if err != nil || !ok || !slices.Contains(result["ignoredFields"].([]string), "parentConnectionId") {
		t.Fatalf("多场景命名空间 ID 未按登记差异处理: %v %v %v", result, ok, err)
	}
	replays[1]["timeOffsetMicros"] = shift.Microseconds() + 1
	if _, _, err := Compare(jsonl(t, observation("research", 0)), jsonl(t, got), report(t, map[string]any{"status": "completed", "mode": "lab_pcap_replay", "replays": replays})); err == nil {
		t.Fatal("场景偏移不一致仍被接受")
	}
	if _, _, err := Compare(jsonl(t), jsonl(t), report(t, map[string]any{"status": "failed", "mode": "lab_pcap_replay", "replay": map[string]any{"timeOffsetMicros": 0}})); err == nil {
		t.Fatal("未完成的回放被接受")
	}
}
