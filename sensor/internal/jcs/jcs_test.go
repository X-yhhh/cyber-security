package jcs

import "testing"

// 对拍向量由 Python rfc8785（执行器同款依赖）生成，覆盖 UTF-16 键序、转义、null 与安全整数边界。
func TestCanonicalMatchesRFC8785Vector(t *testing.T) {
	v := map[string]any{
		"healthVersion": "host-guard-capture-health/1.0.0", "previousSha256": nil, "sequence": 12, "captureGap": false,
		"counterStart": map[string]any{"packetsSeen": 0, "kernelDrops": nil, "capacityDrops": 0},
		"z":            "é€😀\t\"\\\x01", "é": 1, "😀": 2, "｡": 3, "neg": int64(-9007199254740991), "arr": []any{true, nil, "x"},
	}
	want := `{"arr":[true,null,"x"],"captureGap":false,"counterStart":{"capacityDrops":0,"kernelDrops":null,"packetsSeen":0},"healthVersion":"host-guard-capture-health/1.0.0","neg":-9007199254740991,"previousSha256":null,"sequence":12,"z":"é€😀\t\"\\\u0001","é":1,"😀":2,"｡":3}`
	b, err := Canonical(v)
	if err != nil || string(b) != want {
		t.Fatalf("规范化不一致: %s %v", b, err)
	}
	h, err := SHA256(v)
	if err != nil || h != "893b3c09e40d3716c0d288fc95bab0daf932798da0ee1238014bd3bdb360fd03" {
		t.Fatalf("摘要不一致: %s", h)
	}
}

func TestCanonicalRejectsUnsupportedNumbers(t *testing.T) {
	for _, v := range []any{1.5, 1e300, int64(1 << 53), map[string]any{"x": -1.25}} {
		if _, err := Canonical(v); err == nil {
			t.Fatalf("未拒绝 %v", v)
		}
	}
}
