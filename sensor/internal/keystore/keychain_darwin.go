//go:build darwin

package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

const securityTool = "/usr/bin/security"

// 服务名与账户名只允许安全字符，避免拼进 `security -i` 命令行时被解释。
var safeName = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// 凭据字面量字符集（mch_<id>.<secret>）；写入前校验，防止换行或引号注入交互命令。
var safeCredential = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)

// Keychain 使用当前用户（或 root 的系统）默认钥匙串。
type Keychain struct{}

// Default 返回平台默认密钥库。
func Default() Store { return Keychain{} }

func checkNames(service, account string) error {
	if !safeName.MatchString(service) || !safeName.MatchString(account) {
		return errors.New("密钥库条目名称含不允许的字符")
	}
	return nil
}

func (Keychain) Get(service, account string) (string, error) {
	if err := checkNames(service, account); err != nil {
		return "", err
	}
	cmd := exec.Command(securityTool, "find-generic-password", "-s", service, "-a", account, "-w")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 44 { // errSecItemNotFound
			return "", ErrNotFound
		}
		return "", fmt.Errorf("读取钥匙串失败（退出码 %d）", exitCode(err))
	}
	return strings.TrimRight(out.String(), "\r\n"), nil
}

func (Keychain) Put(service, account, secret string) error {
	if err := checkNames(service, account); err != nil {
		return err
	}
	if !safeCredential.MatchString(secret) {
		return errors.New("凭据含不允许的字符")
	}
	// -U：已存在时更新；凭据经 stdin 传入 `security -i`，不出现在 argv。
	cmd := exec.Command(securityTool, "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", service, account, secret))
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &bytes.Buffer{}, &stderr
	if err := cmd.Run(); err != nil || stderr.Len() > 0 {
		return fmt.Errorf("写入钥匙串失败（退出码 %d）", exitCode(err))
	}
	return nil
}

func (Keychain) Delete(service, account string) error {
	if err := checkNames(service, account); err != nil {
		return err
	}
	cmd := exec.Command(securityTool, "delete-generic-password", "-s", service, "-a", account)
	cmd.Stdout, cmd.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		if exitCode(err) == 44 {
			return ErrNotFound
		}
		return fmt.Errorf("删除钥匙串条目失败（退出码 %d）", exitCode(err))
	}
	return nil
}

func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}
