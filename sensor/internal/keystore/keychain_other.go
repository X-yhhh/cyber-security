//go:build !darwin

package keystore

// unsupported 在没有受支持密钥库的平台上 fail-closed：不回退到明文文件或环境变量。
// Windows 凭据管理器实现待 M7 前在 Windows 主机上实测后补充。
type unsupported struct{}

// Default 返回平台默认密钥库。
func Default() Store { return unsupported{} }

func (unsupported) Get(string, string) (string, error) { return "", ErrUnsupported }
func (unsupported) Put(string, string, string) error   { return ErrUnsupported }
func (unsupported) Delete(string, string) error        { return ErrUnsupported }
