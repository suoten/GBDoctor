package gbcode

import "testing"

func TestParseValid(t *testing.T) {
	gb, err := Parse("34020000001320000001")
	if err != nil {
		t.Fatalf("合法编码解析失败: %v", err)
	}
	if gb.Region() != "34020000" {
		t.Errorf("Region = %q, want 34020000", gb.Region())
	}
	if gb.TypeCode() != "132" {
		t.Errorf("TypeCode = %q, want 132", gb.TypeCode())
	}
	if !gb.IsCamera() {
		t.Errorf("IsCamera 应为 true")
	}
	if gb.TypeLabel() != "网络摄像机" {
		t.Errorf("TypeLabel = %q", gb.TypeLabel())
	}
}

func TestParseInvalid(t *testing.T) {
	cases := map[string]string{
		"":                     ErrEmpty.Error(),
		"123":                  ErrLength.Error(),
		"3402000000132000000":  ErrLength.Error(),
		"34020000001320000a01": ErrCharset.Error(),
	}
	for code, want := range cases {
		if _, err := Parse(code); err == nil || err.Error() != want {
			t.Errorf("Parse(%q) err = %v, want %q", code, err, want)
		}
	}
}

func TestPlatformDetection(t *testing.T) {
	gb := MustParse("34020000002000000001")
	if !gb.IsPlatform() {
		t.Errorf("IsPlatform 应为 true")
	}
}

func TestIsValid(t *testing.T) {
	if !IsValid("34020000001320000001") {
		t.Errorf("IsValid 合法编码应为 true")
	}
	if IsValid("abc") {
		t.Errorf("IsValid 非法编码应为 false")
	}
}
