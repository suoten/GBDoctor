package sip

import (
	"fmt"
	"strings"
	"time"
)

// GB2022CheckResult 为 2022 新标专项检测结果。
type GB2022CheckResult struct {
	// 35114 数字证书认证检测
	CertAuthSupported bool // 设备/平台是否支持证书认证
	CertAuthOK        bool // 证书认证是否成功
	CertDetail        string

	// SM4 媒体流加密检测
	SM4Supported  bool // 设备是否支持 SM4 加密
	SM4Negotiated bool // SM4 协商是否成功
	SM4Detail     string

	// SM3 鉴权检测
	SM3Supported bool   // 设备是否声明支持 SM3
	SM3Alg       string // 实际使用的算法

	// TLS 传输检测
	TLSSupported bool

	// 兼容性结论
	DeviceVersion   string
	PlatformVersion string
	Issues          []Issue
	Facts           []string
	TS              time.Time
}

// CheckGB2022 检测 2022 新标合规性。
// 通过注册事实和 SDP 信息推断设备对 2022 新特性（35114/SM4/SM3）的支持情况。
func CheckGB2022(regFact RegisterFact, sdp *SDPInfo) *GB2022CheckResult {
	result := &GB2022CheckResult{
		TS: time.Now(),
	}

	// 1. SM3 鉴权检测
	if regFact.Algorithm == AlgoSM3 || regFact.DeclaredAlg == AlgoSM3 {
		result.SM3Supported = true
		result.SM3Alg = AlgoSM3
		result.Facts = append(result.Facts, "✅ 设备支持 SM3 国密鉴权")
	} else if regFact.Algorithm == AlgoSHA256 {
		result.SM3Alg = AlgoSHA256
		result.Facts = append(result.Facts, "设备使用 SHA-256 鉴权（2016 版）")
	} else {
		result.SM3Alg = AlgoMD5
		result.Facts = append(result.Facts, "设备使用 MD5 鉴权（2011 版）")
	}

	// 2. 从 SDP 检测 SM4 加密
	if sdp != nil {
		// 检查 SDP 中是否有 k= 字段（密钥交换）
		if _, ok := sdp.Attributes["k"]; ok {
			result.SM4Supported = true
			result.SM4Negotiated = true
			result.SM4Detail = "SDP 包含 k= 密钥交换字段"
			result.Facts = append(result.Facts, "✅ SDP 包含 SM4 加密参数")
		}

		// 检查传输协议是否包含 TLS
		if strings.Contains(strings.ToUpper(sdp.Transport), "TLS") {
			result.TLSSupported = true
			result.Facts = append(result.Facts, "✅ 支持 TLS 加密传输")
		}
	}

	// 3. 35114 证书认证推断
	// 如果设备使用 SM3 且 SDP 有加密参数，推断支持 35114
	if result.SM3Supported && result.SM4Supported {
		result.CertAuthSupported = true
		result.CertAuthOK = true
		result.CertDetail = "设备支持 SM3 + SM4，推断兼容 35114 体系"
		result.Facts = append(result.Facts, "✅ 推断支持 35114 数字证书认证体系")
	}

	// 4. 版本推断
	if result.SM3Supported {
		result.DeviceVersion = "2022"
	} else if regFact.Algorithm == AlgoSHA256 {
		result.DeviceVersion = "2016"
	} else {
		result.DeviceVersion = "2011"
	}
	result.Facts = append(result.Facts, fmt.Sprintf("推断设备国标版本: %s", result.DeviceVersion))

	// 5. 生成 Issue
	if !result.SM3Supported && result.SM3Alg == AlgoMD5 {
		result.Issues = append(result.Issues, Issue{
			RuleID:   "GB2022-001-NO-SM3",
			Category: StageGB2022,
			Severity: SeverityAdvice,
			Title:    "设备不支持 SM3 国密鉴权",
			Explain:  "2022 新标引入 SM3 国密算法。当前设备仅使用 MD5，对接 2022 版平台可能需要升级。",
			Advice:   []string{"检查设备固件是否支持 SM3", "如对接 2022 版平台，考虑升级固件"},
		})
	}

	if !result.SM4Supported {
		result.Issues = append(result.Issues, Issue{
			RuleID:   "GB2022-002-NO-SM4",
			Category: StageGB2022,
			Severity: SeverityWarning,
			Title:    "设备不支持 SM4 媒体流加密",
			Explain:  "2022 新标引入 SM4 国密加密媒体流。当前设备 SDP 中未包含加密参数，无法加密传输媒体流。",
			Advice:   []string{"检查设备是否配置了媒体流加密", "确认设备固件支持 SM4"},
		})
	}

	if !result.CertAuthSupported {
		result.Issues = append(result.Issues, Issue{
			RuleID:   "GB2022-003-NO-CERT",
			Category: StageGB2022,
			Severity: SeverityWarning,
			Title:    "设备可能不支持 35114 数字证书认证",
			Explain:  "GB/T 28181-2022 引入了 35114 数字证书认证体系。当前设备未表现出证书认证能力。",
			Advice:   []string{"检查设备是否配置了数字证书", "确认设备固件版本支持 35114"},
		})
	}

	return result
}

// SM4NegotiationCheck 检查 SDP 中的 SM4 加密协商。
func SM4NegotiationCheck(sdp *SDPInfo) []Deviation {
	var devs []Deviation
	if sdp == nil {
		return devs
	}

	// k= 字段用于密钥交换（2022 新增）
	if _, ok := sdp.Attributes["k"]; !ok {
		devs = append(devs, Deviation{
			Kind:   "sm4_no_key",
			Detail: "SDP 缺少 k= 密钥交换字段，SM4 加密协商可能失败",
		})
	}

	// 检查加密属性
	hasEncrypt := false
	for key, val := range sdp.Attributes {
		if strings.Contains(strings.ToLower(key), "encrypt") || strings.Contains(strings.ToLower(val), "sm4") {
			hasEncrypt = true
			break
		}
	}
	if !hasEncrypt && sdp.Attributes["k"] == "" {
		devs = append(devs, Deviation{
			Kind:   "sm4_not_negotiated",
			Detail: "SDP 中未发现 SM4 加密协商参数",
		})
	}

	return devs
}
