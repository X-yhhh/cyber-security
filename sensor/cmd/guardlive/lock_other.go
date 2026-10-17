//go:build !darwin && !linux

package main

import "fmt"

func captureLock(directory, iface string) (func(), error) {
	if directory != "" { return nil, fmt.Errorf("当前系统不支持演示接口锁") }
	return func(){}, nil
}
