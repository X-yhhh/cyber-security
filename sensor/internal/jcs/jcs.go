// Package jcs 实现 RFC 8785 JSON 规范化的受限子集，用于健康窗口哈希链与后端 JsonCanonicalizer 对齐。
//
// 只接受对象、数组、字符串、布尔、null 与 ±2^53 内的整数；浮点数、指数或超范围整数直接报错，
// 不做可能与 ES6 数值格式不一致的近似输出。键按 UTF-16 码元排序，字符串只转义 RFC 8785 要求的字符。
package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

const maxSafe = 1<<53 - 1

// Canonical 先按 encoding/json 序列化 v，再输出规范化字节。
func Canonical(v any) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	d := json.NewDecoder(&raw)
	d.UseNumber()
	var tree any
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := write(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SHA256 返回规范化字节的小写十六进制 SHA-256。
func SHA256(v any) (string, error) {
	b, err := Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func write(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(x))
	case json.Number:
		s := string(x)
		if !integer.MatchString(s) {
			return fmt.Errorf("JCS 子集只接受整数")
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSafe || n < -maxSafe {
			return fmt.Errorf("JCS 整数超出安全范围")
		}
		out.WriteString(strconv.FormatInt(n, 10))
	case string:
		return writeString(out, x)
	case []any:
		out.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeString(out, k); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := write(out, x[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("JCS 不支持的类型 %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func writeString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("JCS 字符串不是合法 UTF-8")
	}
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}
