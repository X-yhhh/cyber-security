// guardreplaydiff 逐字段比对 guardlive -pcap 的 1 倍速回放输出与 guardextract 对同一文件的离线输出。
//
// 回放观察的 firstSeenAt/lastPacketAt/asOf 减去运行摘要中的 timeOffsetMicros 后还原为原事件时间；
// emittedAt 是真实墙钟，两侧都不参与比较。离线侧按回放所用的 captureScope 做同一过滤。
// 只读两份本地 JSONL，不访问网络；任一字段不一致返回非零。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

func open(path string) (*os.File, *bufio.Scanner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 16<<20)
	return f, s, nil
}

func normalize(line []byte, shift time.Duration) ([]byte, error) {
	var o hostguard.Observation
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return nil, err
	}
	o.FirstSeenAt, o.LastPacketAt, o.AsOf = o.FirstSeenAt.Add(-shift).UTC(), o.LastPacketAt.Add(-shift).UTC(), o.AsOf.Add(-shift).UTC()
	if o.TargetExpiresAt != nil {
		v := o.TargetExpiresAt.Add(-shift).UTC()
		o.TargetExpiresAt = &v
	}
	o.EmittedAt = time.Time{}
	return json.Marshal(o)
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

func run() (bool, error) {
	offline := flag.String("offline", "", "guardextract 输出 JSONL")
	replay := flag.String("replay", "", "guardlive -pcap 输出 JSONL")
	report := flag.String("report", "", "guardlive -pcap 的 -report 运行摘要")
	flag.Parse()
	if *offline == "" || *replay == "" || *report == "" {
		return false, fmt.Errorf("须指定 offline、replay、report")
	}
	rb, err := os.ReadFile(*report)
	if err != nil {
		return false, err
	}
	var rep struct {
		Status       string `json:"status"`
		Mode         string `json:"mode"`
		CaptureScope string `json:"captureScope"`
		Replay       *struct {
			TimeOffsetMicros int64 `json:"timeOffsetMicros"`
		} `json:"replay"`
	}
	if err = json.Unmarshal(rb, &rep); err != nil || rep.Replay == nil || rep.Mode != "research_pcap_replay" || rep.Status != "completed" {
		return false, fmt.Errorf("运行摘要不是已完成的 pcap 回放")
	}
	shift := time.Duration(rep.Replay.TimeOffsetMicros) * time.Microsecond
	fo, so, err := open(*offline)
	if err != nil {
		return false, err
	}
	defer fo.Close()
	fr, sr, err := open(*replay)
	if err != nil {
		return false, err
	}
	defer fr.Close()
	ho, hr := sha256.New(), sha256.New()
	compared, skipped := 0, 0
	result := map[string]any{"captureScope": rep.CaptureScope, "timeOffsetMicros": rep.Replay.TimeOffsetMicros, "ignoredFields": []string{"emittedAt"}}
	ok := true
	for {
		var want []byte
		for so.Scan() {
			line := so.Bytes()
			ho.Write(line)
			ho.Write([]byte{'\n'})
			var o hostguard.Observation
			if err := json.Unmarshal(line, &o); err != nil {
				return false, err
			}
			if rep.CaptureScope == "all_inbound_tcp" && (o.Transport != "tcp" || o.Direction == "outbound") {
				skipped++
				continue
			}
			if want, err = normalize(line, 0); err != nil {
				return false, err
			}
			break
		}
		if err := so.Err(); err != nil {
			return false, err
		}
		var got []byte
		if sr.Scan() {
			hr.Write(sr.Bytes())
			hr.Write([]byte{'\n'})
			if got, err = normalize(sr.Bytes(), shift); err != nil {
				return false, err
			}
		}
		if err := sr.Err(); err != nil {
			return false, err
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
	en := json.NewEncoder(os.Stdout)
	en.SetIndent("", "  ")
	return ok, en.Encode(result)
}

func main() {
	ok, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardreplaydiff:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}
