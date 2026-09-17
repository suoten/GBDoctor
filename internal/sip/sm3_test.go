package sip

import (
	"strings"
	"testing"
)

// 测试向量取自 GB/T 32907-2016 附录 A。
func TestSM3Vectors(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		// 附录 B：64 字节长报文（跨分组填充）
		{strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, c := range cases {
		if got := SM3Hex([]byte(c.in)); got != c.want {
			t.Errorf("SM3(len=%d) = %s, want %s", len(c.in), got, c.want)
		}
	}
}

func TestSM3MultiBlock(t *testing.T) {
	// 3 个完整分组 + 部分组，验证连续分组正确性（无标准向量，校验结构性质）
	a := SM3Hex([]byte(strings.Repeat("x", 200)))
	b := SM3Hex([]byte(strings.Repeat("x", 201)))
	if a == b {
		t.Errorf("不同长度消息摘要不应相同")
	}
	if len(a) != 64 || len(b) != 64 {
		t.Fatalf("摘要应为 64 hex")
	}
}
