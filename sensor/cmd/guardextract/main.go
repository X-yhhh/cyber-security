// guardextract 是独立 research-only v5 路由，不读取活动 v4 配置、不上传或调用执行器。
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type config struct {
	AssetID        string       `json:"assetId"`
	SensorID       string       `json:"sensorId"`
	BootID         string       `json:"bootId"`
	CaptureScopeID string       `json:"captureScopeId"`
	LocalAddresses []netip.Addr `json:"localAddresses"`
	SecretFile     string       `json:"secretFile"`
	KeyEpoch       int          `json:"keyEpoch"`
}

func digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
func run() error {
	cp := flag.String("config", "", "受控 research 配置；身份和密钥不可在重试时改变")
	in := flag.String("pcap", "", "完整 PCAP/PCAPNG，只读")
	out := flag.String("out", "", "不存在的观察 JSONL 文件")
	ledger := flag.String("ledger", "", "可选本机端点旁路，仅写入受控忽略目录")
	report := flag.String("report", "", "不存在的去敏运行摘要")
	startAt := flag.String("start", "", "可选分区起点 RFC3339；该时刻前不读入引擎")
	endAt := flag.String("end", "", "可选分区终点 RFC3339；该时刻后不读入引擎")
	flag.Parse()
	if *cp == "" || *in == "" || *out == "" || *report == "" {
		return fmt.Errorf("必须指定 config/pcap/out/report")
	}
	var begin, end time.Time
	if *startAt != "" {
		var err error
		begin, err = time.Parse(time.RFC3339Nano, *startAt)
		if err != nil {
			return fmt.Errorf("start 时间无效")
		}
	}
	if *endAt != "" {
		var err error
		end, err = time.Parse(time.RFC3339Nano, *endAt)
		if err != nil {
			return fmt.Errorf("end 时间无效")
		}
	}
	if !begin.IsZero() && !end.IsZero() && !begin.Before(end) {
		return fmt.Errorf("分区范围无效")
	}
	b, err := os.ReadFile(*cp)
	if err != nil {
		return err
	}
	var c config
	if err = json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("配置格式错误")
	}
	secret, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return fmt.Errorf("不能读取本机 HMAC 密钥")
	}
	f, err := create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(w)
	var lf *os.File
	var lw *bufio.Writer
	var le *json.Encoder
	if *ledger != "" {
		lf, err = create(*ledger)
		if err != nil {
			return err
		}
		defer lf.Close()
		lw = bufio.NewWriterSize(lf, 1<<20)
		le = json.NewEncoder(lw)
	}
	distribution := map[string]int64{}
	e, err := hostguard.New(hostguard.Config{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID, CaptureScopeID: c.CaptureScopeID, LocalAddresses: c.LocalAddresses, Environment: "research", PeerSecret: secret, KeyEpoch: c.KeyEpoch,
		Emit: func(v hostguard.Emission) error {
			o := v.Observation
			quality := "clean"
			if o.Quality.Defective() {
				quality = "defective"
			}
			distribution[o.Transport+"/"+o.Direction+"/"+o.Profile+"/"+quality]++
			if err := enc.Encode(o); err != nil {
				return err
			}
			if le != nil {
				return le.Encode(struct {
					ObservationID     string `json:"observationId"`
					ParentID          string `json:"parentConnectionId"`
					FlowID            string `json:"flowId"`
					First, Last, AsOf time.Time
					Endpoints         hostguard.Endpoints
				}{o.ObservationID, o.ParentConnectionID, o.FlowID, o.FirstSeenAt, o.LastPacketAt, o.AsOf, v.Endpoints})
			}
			return nil
		}})
	if err != nil {
		return err
	}
	start := time.Now()
	if err = hostguard.WalkPCAP(*in, func(data []byte, ci gopacket.CaptureInfo, seq uint64) error {
		if !begin.IsZero() && ci.Timestamp.Before(begin) || !end.IsZero() && ci.Timestamp.After(end) {
			return nil
		}
		return e.Frame(data, ci.Length, ci.Timestamp, seq)
	}); err != nil {
		return err
	}
	if err = e.Close(); err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if lw != nil {
		if err = lw.Flush(); err != nil {
			return err
		}
		if err = lf.Sync(); err != nil {
			return err
		}
	}
	pcapHash, err := digest(*in)
	if err != nil {
		return err
	}
	outputHash, err := digest(*out)
	if err != nil {
		return err
	}
	configHash, err := digest(*cp)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binaryHash, err := digest(exe)
	if err != nil {
		return err
	}
	r := map[string]any{"version": hostguard.Version, "status": "completed", "mode": "research_offline", "os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "stats": e.Stats, "distribution": distribution, "pcapSha256": pcapHash, "observationsSha256": outputHash, "configSha256": configHash, "binarySha256": binaryHash, "elapsedSeconds": time.Since(start).Seconds(), "historicalCaptureDrops": nil, "automaticExecutionSupported": false}
	r["partitionStart"] = *startAt
	r["partitionEnd"] = *endAt
	if *ledger != "" {
		h, err := digest(*ledger)
		if err != nil {
			return err
		}
		r["localLedgerSha256"] = h
	}
	rf, err := create(*report)
	if err != nil {
		return err
	}
	defer rf.Close()
	en := json.NewEncoder(rf)
	en.SetIndent("", "  ")
	if err = en.Encode(r); err != nil {
		return err
	}
	if err = rf.Sync(); err != nil {
		return err
	}
	fmt.Printf("status=completed frames=%d observations=%d mode=research\n", e.Stats["frames"], e.Stats["observations"])
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardextract:", err)
		os.Exit(1)
	}
}
