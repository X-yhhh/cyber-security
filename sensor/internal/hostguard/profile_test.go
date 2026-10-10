package hostguard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// 契约 profile 变化时提取器常量必须同步；训练分支若未携带 docs 则跳过。
func TestFeatureProfileHashMatchesContract(t *testing.T) {
	b, err := os.ReadFile("../../../docs/contracts/feature-profile.json")
	if os.IsNotExist(err) {
		t.Skip("当前检出不含 docs/contracts")
	}
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != FeatureProfileSHA256 {
		t.Fatal("FeatureProfileSHA256 与 docs/contracts/feature-profile.json 不一致")
	}
}
