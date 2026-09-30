// Package keystore 保存传感器机器凭据。凭据只放在操作系统密钥库（macOS 钥匙串）中，
// 不写配置文件、不读环境变量、不进日志。
//
// macOS 实现调用 /usr/bin/security：读取用 find-generic-password -w（凭据经 stdout 返回），
// 写入用 `security -i` 从 stdin 读命令，凭据不出现在进程参数列表中。
package keystore

import (
	"errors"
	"sync"
)

// ErrNotFound 表示密钥库中没有该条目。
var ErrNotFound = errors.New("密钥库中没有传感器凭据")

// ErrUnsupported 表示当前平台没有受支持的密钥库实现（fail-closed，不回退到明文文件）。
var ErrUnsupported = errors.New("当前平台没有受支持的密钥库")

// Store 按 (service, account) 保存一个秘密字符串。
type Store interface {
	Get(service, account string) (string, error)
	Put(service, account, secret string) error
	Delete(service, account string) error
}

// Memory 是只用于测试的内存实现。
type Memory struct {
	mu sync.Mutex
	m  map[[2]string]string
}

func NewMemory() *Memory { return &Memory{m: map[[2]string]string{}} }

func (s *Memory) Get(service, account string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[[2]string{service, account}]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (s *Memory) Put(service, account, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[[2]string{service, account}] = secret
	return nil
}

func (s *Memory) Delete(service, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[[2]string{service, account}]; !ok {
		return ErrNotFound
	}
	delete(s.m, [2]string{service, account})
	return nil
}
