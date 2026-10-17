package main

import (
	"fmt"
	"os"
)

type outputFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// rotatingFile 仅约束持续采集的本机诊断副本；每条 JSON 保持完整，上传原字节 spool 不在此处删除。
type rotatingFile struct {
	file    *os.File
	path    string
	size    int64
	limit   int64
	backups int
}

func openOutput(path string, managed bool) (outputFile, error) {
	f, err := create(path)
	if err != nil || !managed {
		return f, err
	}
	return &rotatingFile{file: f, path: path, limit: 8 << 20, backups: 3}, nil
}

func (f *rotatingFile) Write(b []byte) (int, error) {
	if f.size > 0 && f.size+int64(len(b)) > f.limit {
		if err := f.file.Sync(); err != nil {
			return 0, err
		}
		if err := f.file.Close(); err != nil {
			return 0, err
		}
		for i := f.backups; i > 0; i-- {
			source := f.path
			if i > 1 {
				source = fmt.Sprintf("%s.%d", f.path, i-1)
			}
			if err := os.Rename(source, fmt.Sprintf("%s.%d", f.path, i)); err != nil && !os.IsNotExist(err) {
				return 0, err
			}
		}
		var err error
		f.file, err = create(f.path)
		if err != nil {
			return 0, err
		}
		f.size = 0
	}
	n, err := f.file.Write(b)
	f.size += int64(n)
	return n, err
}

func (f *rotatingFile) Sync() error  { return f.file.Sync() }
func (f *rotatingFile) Close() error { return f.file.Close() }
