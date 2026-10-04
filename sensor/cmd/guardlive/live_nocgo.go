//go:build !cgo

package main

import (
	"context"
	"fmt"
	"github.com/xyh/cyber-security/sensor/internal/hostguard"
)

func capture(context.Context, config, *hostguard.Engine, func(any) error) error {
	return fmt.Errorf("live 入口需要 cgo 和目标平台 libpcap/Npcap；离线构建不能当 live 验收")
}
