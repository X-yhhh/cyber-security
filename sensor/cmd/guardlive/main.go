// guardlive 只在显式授权的接口和期限内输出 v5 research 观察；不接入业务或执行器。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

type config struct {
	AssetID           string       `json:"assetId"`
	SensorID          string       `json:"sensorId"`
	BootID            string       `json:"bootId"`
	CaptureScopeID    string       `json:"captureScopeId"`
	LocalAddresses    []netip.Addr `json:"localAddresses"`
	PeerAddresses     []netip.Addr `json:"peerAddresses"`
	ServicePort       uint16       `json:"servicePort"`
	ServiceEndpoint   string       `json:"serviceEndpoint"`
	SecretFile        string       `json:"secretFile"`
	KeyEpoch          int          `json:"keyEpoch"`
	Interface         string       `json:"interface"`
	AllowedInterfaces []string     `json:"allowedInterfaces"`
	AuthorizedUntil   time.Time    `json:"authorizedUntil"`
}

func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func run() error {
	cp := flag.String("config", "", "私有资产、接口白名单及截止授权")
	out := flag.String("out", "", "不存在的观察 JSONL")
	trace := flag.String("trace", "", "不存在的私有头部轨迹；含端点，不能进 Git")
	replay := flag.String("replay", "", "复算既有同包轨迹，离线模式不开抓包")
	duration := flag.Duration("duration", 180*time.Second, "采集期限 1秒..30分钟")
	flag.Parse()
	if *cp == "" || *out == "" || (*trace == "" && *replay == "") || (*trace != "" && *replay != "") {
		return fmt.Errorf("须指定 config/out 及 trace 或 replay")
	}
	f, err := os.Open(*cp)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var c config
	if err = decoder.Decode(&c); err != nil {
		return fmt.Errorf("授权配置无效")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("授权配置存在尾随内容")
	}
	secret, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return fmt.Errorf("本机 HMAC 密钥不可读")
	}
	w, err := create(*out)
	if err != nil {
		return err
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	e, err := hostguard.New(hostguard.Config{AssetID: c.AssetID, SensorID: c.SensorID, BootID: c.BootID,
		CaptureScopeID: c.CaptureScopeID, LocalAddresses: c.LocalAddresses, PeerSecret: secret, KeyEpoch: c.KeyEpoch,
		Environment: "research", Emit: func(v hostguard.Emission) error { return enc.Encode(v.Observation) }})
	if err != nil {
		return err
	}
	if *replay != "" {
		r, err := os.Open(*replay)
		if err != nil {
			return err
		}
		defer r.Close()
		d := json.NewDecoder(r)
		d.DisallowUnknownFields()
		closed := false
		for {
			var v hostguard.LiveEvent
			err := d.Decode(&v)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if closed {
				return fmt.Errorf("close 后仍有轨迹")
			}
			if err = e.ApplyLiveEvent(v); err != nil {
				return err
			}
			closed = v.Kind == "close"
		}
		if !closed {
			return fmt.Errorf("轨迹未完整关闭")
		}
	} else {
		if *duration < time.Second || *duration > 30*time.Minute || time.Now().Add(*duration).After(c.AuthorizedUntil) {
			return fmt.Errorf("采集时限超出授权")
		}
		for _, addr := range c.LocalAddresses {
			if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
				return fmt.Errorf("本机地址不明确")
			}
		}
		t, err := create(*trace)
		if err != nil {
			return err
		}
		defer t.Close()
		te := json.NewEncoder(t)
		ctx, cancel := context.WithTimeout(context.Background(), *duration)
		defer cancel()
		if err = capture(ctx, c, e, te.Encode); err != nil {
			return err
		}
		if err = t.Sync(); err != nil {
			return err
		}
	}
	if err = w.Sync(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "completed", "mode": "research", "stats": e.Stats, "automaticExecutionSupported": false})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guardlive:", err)
		os.Exit(1)
	}
}
