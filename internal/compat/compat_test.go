package compat

import (
	"testing"

	"gbdoctor/internal/sip"
)

func TestDetectVersionFromRegister(t *testing.T) {
	// SM3 → 2022
	f := sip.RegisterFact{Algorithm: sip.AlgoSM3}
	if v := DetectVersion(f); v != GB2022 {
		t.Errorf("SM3 → %s, want 2022", v)
	}

	// SHA-256 → 2016
	f = sip.RegisterFact{Algorithm: sip.AlgoSHA256}
	if v := DetectVersion(f); v != GB2016 {
		t.Errorf("SHA-256 → %s, want 2016", v)
	}

	// MD5 → 2011
	f = sip.RegisterFact{Algorithm: sip.AlgoMD5}
	if v := DetectVersion(f); v != GB2011 {
		t.Errorf("MD5 → %s, want 2011", v)
	}
}

func TestDetectVersionFromSDP(t *testing.T) {
	// TLS 传输 → 2022
	sdp := &sip.SDPInfo{Transport: "RTP/TLS"}
	if v := DetectVersionFromSDP(sdp); v != GB2022 {
		t.Errorf("TLS → %s, want 2022", v)
	}

	// TCP 传输 → 2016
	sdp = &sip.SDPInfo{Transport: "RTP/TCP"}
	if v := DetectVersionFromSDP(sdp); v != GB2016 {
		t.Errorf("TCP → %s, want 2016", v)
	}

	// UDP 传输 → 2011
	sdp = &sip.SDPInfo{Transport: "RTP/AVP"}
	if v := DetectVersionFromSDP(sdp); v != GB2011 {
		t.Errorf("UDP → %s, want 2011", v)
	}

	// nil SDP → 2011
	if v := DetectVersionFromSDP(nil); v != GB2011 {
		t.Errorf("nil SDP → %s, want 2011", v)
	}
}

func TestCheckCompatibilityAllMatch(t *testing.T) {
	result := CheckCompatibility(GB2011, GB2022)
	if len(result.Diffs) == 0 {
		t.Error("2011 vs 2022 应有差异")
	}
	if len(result.Issues) == 0 {
		t.Error("应有 Issue")
	}
	if len(result.Conclusions) == 0 {
		t.Error("应有结论")
	}
}

func TestCheckCompatibilitySameVersion(t *testing.T) {
	result := CheckCompatibility(GB2016, GB2016)
	if len(result.Diffs) != 0 {
		t.Errorf("同版本不应有差异, got %d", len(result.Diffs))
	}
	if len(result.Conclusions) == 0 {
		t.Error("应有结论（兼容）")
	}
}

func TestCheckCompatibility2022vs2011(t *testing.T) {
	result := CheckCompatibility(GB2022, GB2011)
	if len(result.Diffs) == 0 {
		t.Error("2022 vs 2011 应有差异")
	}
	// 2022 设备有 SM3、SM4 等特性，2011 平台不支持
	found := false
	for _, iss := range result.Issues {
		if iss.Title != "" {
			found = true
		}
	}
	if !found {
		t.Error("应至少有一个非空标题的 Issue")
	}
}

func TestVersionLabel(t *testing.T) {
	if l := VersionLabel(GB2011); l != "GB/T 28181-2011" {
		t.Errorf("GB2011 label = %q", l)
	}
	if l := VersionLabel(GB2016); l != "GB/T 28181-2016" {
		t.Errorf("GB2016 label = %q", l)
	}
	if l := VersionLabel(GB2022); l != "GB/T 28181-2022" {
		t.Errorf("GB2022 label = %q", l)
	}
}

func TestKnownVersionDiffs(t *testing.T) {
	if len(KnownVersionDiffs) < 5 {
		t.Errorf("已知差异项应至少 5 条, got %d", len(KnownVersionDiffs))
	}
	// 验证关键特性覆盖
	features := map[string]bool{}
	for _, d := range KnownVersionDiffs {
		features[d.Feature] = true
	}
	required := []string{"鉴权算法", "媒体流加密", "身份认证"}
	for _, req := range required {
		if !features[req] {
			t.Errorf("缺少关键特性: %s", req)
		}
	}
}

func TestIsFeatureSupported(t *testing.T) {
	diff := VersionDiff{
		Feature: "test",
		GB2011:  "不支持",
		GB2016:  "MD5",
		GB2022:  "SM3",
	}
	if isFeatureSupported(diff, GB2011) {
		t.Error("2011 不支持应返回 false")
	}
	if !isFeatureSupported(diff, GB2016) {
		t.Error("2016 支持应返回 true")
	}
	if !isFeatureSupported(diff, GB2022) {
		t.Error("2022 支持应返回 true")
	}
}
