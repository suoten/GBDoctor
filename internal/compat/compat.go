// Package compat 实现 GB/T 28181 多版本兼容性检测（V1.2）。
//
// 检测国标 2011/2016/2022 三个版本的行为差异：
//   - 鉴权算法：2011 仅 MD5，2016 新增 SHA-256，2022 新增 SM3
//   - 媒体加密：2022 引入 SM4
//   - 身份认证：2022 引入 35114 数字证书
//   - XML 命名空间：不同版本差异
//   - Catalog 字段差异
package compat

import (
	"fmt"
	"strings"

	"gbdoctor/internal/sip"
)

// GBVersion 为国标版本。
type GBVersion string

const (
	GB2011 GBVersion = "2011"
	GB2016 GBVersion = "2016"
	GB2022 GBVersion = "2022"
)

// VersionDiff 为版本间差异项。
type VersionDiff struct {
	Feature  string
	GB2011   string
	GB2016   string
	GB2022   string
	Detail   string
	Severity sip.Severity
}

// KnownVersionDiffs 为已知的版本间差异清单。
var KnownVersionDiffs = []VersionDiff{
	{
		Feature:  "鉴权算法",
		GB2011:   "MD5",
		GB2016:   "MD5, SHA-256",
		GB2022:   "MD5, SHA-256, SM3",
		Detail:   "2022 新增 SM3 国密算法，老平台不支持可能导致鉴权失败",
		Severity: sip.SeverityWarning,
	},
	{
		Feature:  "媒体流加密",
		GB2011:   "不支持",
		GB2016:   "不支持",
		GB2022:   "SM4 国密加密",
		Detail:   "2022 引入 SM4 媒体流加密，需配合 35114 密钥分发",
		Severity: sip.SeverityBlocking,
	},
	{
		Feature:  "身份认证",
		GB2011:   "Digest 认证",
		GB2016:   "Digest 认证",
		GB2022:   "35114 数字证书 + Digest",
		Detail:   "2022 新增数字证书认证体系（GB/T 35114）",
		Severity: sip.SeverityBlocking,
	},
	{
		Feature:  "音视频编码",
		GB2011:   "H.264, G.711",
		GB2016:   "H.264, H.265, G.711, AAC",
		GB2022:   "H.264, H.265, SVAC, G.711, AAC, OPUS",
		Detail:   "2022 新增 SVAC 和 OPUS 编码支持",
		Severity: sip.SeverityAdvice,
	},
	{
		Feature:  "传输协议",
		GB2011:   "UDP",
		GB2016:   "UDP, TCP",
		GB2022:   "UDP, TCP, TLS",
		Detail:   "2022 新增 TLS 加密传输支持",
		Severity: sip.SeverityAdvice,
	},
	{
		Feature:  "XML 命名空间",
		GB2011:   "无标准",
		GB2016:   "部分标准",
		GB2022:   "完整标准",
		Detail:   "不同版本 XML 字段可能有大小写差异和新增字段",
		Severity: sip.SeverityWarning,
	},
	{
		Feature:  "目录字段",
		GB2011:   "基础字段",
		GB2016:   "新增 BusinessGroup",
		GB2022:   "新增更多字段",
		Detail:   "2022 版目录字段更丰富，老设备可能缺少新字段",
		Severity: sip.SeverityAdvice,
	},
}

// CompatCheckResult 为兼容性检测结果。
type CompatCheckResult struct {
	DeviceVersion   GBVersion // 检测到的设备版本
	PlatformVersion GBVersion // 平台版本
	Diffs           []VersionDiff
	Issues          []sip.Issue
	Conclusions     []string
}

// DetectVersion 从注册事实中推断设备国标版本。
func DetectVersion(f sip.RegisterFact) GBVersion {
	// SM3 算法 → 2022
	if f.DeclaredAlg == sip.AlgoSM3 || f.Algorithm == sip.AlgoSM3 {
		return GB2022
	}
	// SHA-256 → 2016+
	if f.DeclaredAlg == sip.AlgoSHA256 || f.Algorithm == sip.AlgoSHA256 {
		return GB2016
	}
	// 默认 2011（MD5）
	return GB2011
}

// DetectVersionFromSDP 从 SDP 信息推断设备国标版本。
func DetectVersionFromSDP(sdp *sip.SDPInfo) GBVersion {
	if sdp == nil {
		return GB2011
	}
	// 检查是否包含加密相关属性
	attrs := sdp.Attributes
	if _, ok := attrs["k"]; ok {
		return GB2022 // k= 字段用于密钥交换，2022 新增
	}
	// 检查传输协议
	if strings.Contains(strings.ToUpper(sdp.Transport), "TLS") {
		return GB2022
	}
	if strings.Contains(strings.ToUpper(sdp.Transport), "TCP") {
		return GB2016
	}
	return GB2011
}

// CheckCompatibility 检测设备版本与平台版本的兼容性。
func CheckCompatibility(deviceVer, platformVer GBVersion) *CompatCheckResult {
	result := &CompatCheckResult{
		DeviceVersion:   deviceVer,
		PlatformVersion: platformVer,
	}

	// 判断版本差异的影响
	for _, diff := range KnownVersionDiffs {
		if !isFeatureSupported(diff, deviceVer) && isFeatureSupported(diff, platformVer) {
			// 平台支持但设备不支持
			result.Diffs = append(result.Diffs, diff)
			result.Issues = append(result.Issues, sip.Issue{
				RuleID:   fmt.Sprintf("COMPAT-%s", diff.Feature),
				Category: sip.StageGB2022,
				Severity: diff.Severity,
				Title:    fmt.Sprintf("设备不支持 %s（平台 %s 版本要求）", diff.Feature, platformVer),
				Explain:  diff.Detail,
				Advice:   []string{fmt.Sprintf("升级设备固件以支持 %s 版本特性", platformVer)},
			})
			result.Conclusions = append(result.Conclusions,
				fmt.Sprintf("⚠️ %s: 设备(%s)不支持，平台(%s)要求", diff.Feature, deviceVer, platformVer))
		} else if isFeatureSupported(diff, deviceVer) && !isFeatureSupported(diff, platformVer) {
			// 设备支持但平台不支持
			result.Diffs = append(result.Diffs, diff)
			result.Issues = append(result.Issues, sip.Issue{
				RuleID:   fmt.Sprintf("COMPAT-%s", diff.Feature),
				Category: sip.StageGB2022,
				Severity: diff.Severity,
				Title:    fmt.Sprintf("平台不支持 %s（设备 %s 版本要求）", diff.Feature, deviceVer),
				Explain:  diff.Detail,
				Advice:   []string{fmt.Sprintf("升级平台以支持 %s 版本特性", deviceVer)},
			})
			result.Conclusions = append(result.Conclusions,
				fmt.Sprintf("⚠️ %s: 设备(%s)支持，平台(%s)不支持", diff.Feature, deviceVer, platformVer))
		}
	}

	if len(result.Diffs) == 0 {
		result.Conclusions = append(result.Conclusions,
			fmt.Sprintf("✅ 设备(%s)与平台(%s)版本兼容", deviceVer, platformVer))
	}

	return result
}

// isFeatureSupported 判断某版本是否支持某个特性。
func isFeatureSupported(diff VersionDiff, ver GBVersion) bool {
	switch ver {
	case GB2011:
		return diff.GB2011 != "不支持" && diff.GB2011 != "无标准"
	case GB2016:
		return diff.GB2016 != "不支持" && diff.GB2016 != "无标准"
	case GB2022:
		return diff.GB2022 != "不支持" && diff.GB2022 != "无标准"
	}
	return false
}

// VersionLabel 返回版本的中文标签。
func VersionLabel(ver GBVersion) string {
	switch ver {
	case GB2011:
		return "GB/T 28181-2011"
	case GB2016:
		return "GB/T 28181-2016"
	case GB2022:
		return "GB/T 28181-2022"
	}
	return string(ver)
}
