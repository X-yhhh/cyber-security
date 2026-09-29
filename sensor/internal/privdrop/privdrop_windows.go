//go:build windows

package privdrop

import "errors"

// Target 是降权目标（Windows 暂不支持）。
type Target struct {
	UID, GID int
	Name     string
	Home     string
}

var errUnsupported = errors.New("Windows 上的降权待 Windows 实测时实现")

// FromSudo 在 Windows 上 fail-closed。
func FromSudo() (Target, error) { return Target{}, errUnsupported }

// Drop 在 Windows 上 fail-closed。
func Drop(Target) error { return errUnsupported }
