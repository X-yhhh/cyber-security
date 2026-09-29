package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// State 是跨进程重启保留的上报状态：每个配置版本的下一个批次序号。
//
// 序号在批次创建时分配并先落盘再发送：重启后不会复用已分配的序号（后端拒绝序号回退与同号不同内容），
// 发送失败重试时沿用同一序号与幂等键。文件只含序号，不含凭据、地址或特征。
type State struct {
	mu   sync.Mutex
	path string
	data stateFile
}

type stateFile struct {
	NextSequence map[string]int64 `json:"nextSequence"`
}

// LoadState 读取 stateDir/state.json；不存在时从空状态开始。目录不存在时以 0700 创建。
func LoadState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("无法创建状态目录: %w", err)
	}
	s := &State{path: filepath.Join(dir, "state.json"), data: stateFile{NextSequence: map[string]int64{}}}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("无法读取状态文件: %w", err)
	}
	if err := json.Unmarshal(raw, &s.data); err != nil || s.data.NextSequence == nil {
		// 状态损坏时不猜测序号：继续运行可能提交回退的序号，fail-closed 交给人工处理。
		return nil, errors.New("状态文件损坏，拒绝猜测批次序号")
	}
	for k, v := range s.data.NextSequence {
		if !safeVersion.MatchString(k) || v < 0 {
			return nil, errors.New("状态文件含非法配置版本或负序号")
		}
	}
	return s, nil
}

// Allocate 为 configVersion 分配下一个序号并先持久化，返回分配到的序号。序号从 1 开始（后端 `sequence` 为 @Positive）。
func (s *State) Allocate(configVersion string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := max(s.data.NextSequence[configVersion], 1)
	s.data.NextSequence[configVersion] = seq + 1
	if err := s.save(); err != nil {
		s.data.NextSequence[configVersion] = seq
		return 0, err
	}
	return seq, nil
}

// save 写临时文件后 rename，保证崩溃时文件要么是旧内容要么是新内容。
func (s *State) save() error {
	raw, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.json")
	if err != nil {
		return fmt.Errorf("无法写入状态文件: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
