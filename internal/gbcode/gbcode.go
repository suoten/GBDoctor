// Package gbcode 实现 GB/T 28181 20 位国标编码值对象。
//
// 编码构成（产品规划/规则库口径）：
//   - 第 1-8 位：行政区划码
//   - 第 9-10 位：行业/保留位（部分实现为 00）
//   - 第 11-13 位：设备类型码（132=网络摄像机，131=视频通道，200/0020=平台…）
//   - 第 11-20 位：序号
//
// 非法编码在构造时即拒绝，保证不进入诊断领域层（design §2.3.2 值对象）。
package gbcode

import (
	"errors"
	"strings"
)

// 常见设备类型码（第 11-13 位）。
const (
	TypeVideoChannel    = "131" // 视频通道
	TypeNetworkCamera   = "132" // 网络摄像机
	TypeAlarmIn         = "133" // 报警输入
	TypeAlarmOut        = "134" // 报警输出
	TypeNVR             = "135" // 数字硬盘录像机
	TypeBusinessGroup   = "136" // 业务分组
	TypeVirtualOrg      = "137" // 虚拟组织
	TypeCascadePlatform = "200" // 国标联网系统/平台
)

var (
	ErrEmpty   = errors.New("国标编码为空")
	ErrLength  = errors.New("国标编码必须为 20 位")
	ErrCharset = errors.New("国标编码必须为纯数字")
)

// GBCode 为不可变值对象。
type GBCode struct {
	code string
}

// Parse 解析并校验编码；失败返回 error（含具体原因）。
func Parse(code string) (GBCode, error) {
	c := strings.TrimSpace(code)
	if c == "" {
		return GBCode{}, ErrEmpty
	}
	if len(c) != 20 {
		return GBCode{}, ErrLength
	}
	for i := 0; i < len(c); i++ {
		if c[i] < '0' || c[i] > '9' {
			return GBCode{}, ErrCharset
		}
	}
	return GBCode{code: c}, nil
}

// MustParse 仅供测试/内置常量使用。
func MustParse(code string) GBCode {
	gb, err := Parse(code)
	if err != nil {
		panic(err)
	}
	return gb
}

// String 返回原编码。
func (g GBCode) String() string {
	if g.code == "" {
		return ""
	}
	return g.code
}

// Valid 报告编码是否合法。
func (g GBCode) Valid() bool { return len(g.code) == 20 }

// Region 返回第 1-8 位行政区划码。
func (g GBCode) Region() string {
	if !g.Valid() {
		return ""
	}
	return g.code[:8]
}

// TypeCode 返回第 11-13 位设备类型码。
func (g GBCode) TypeCode() string {
	if !g.Valid() {
		return ""
	}
	return g.code[10:13]
}

// Serial 返回第 11-20 位序号。
func (g GBCode) Serial() string {
	if !g.Valid() {
		return ""
	}
	return g.code[10:]
}

// IsPlatform 判定编码是否为平台类（类型码 200 或 11-12 位为 "20"）。
func (g GBCode) IsPlatform() bool {
	if !g.Valid() {
		return false
	}
	return strings.HasPrefix(g.TypeCode(), "20")
}

// IsCamera 判定是否为网络摄像机（132）。
func (g GBCode) IsCamera() bool { return g.TypeCode() == TypeNetworkCamera }

// IsVideoChannel 判定是否为视频通道（131）。
func (g GBCode) IsVideoChannel() bool { return g.TypeCode() == TypeVideoChannel }

// TypeLabel 返回类型码的人话标签（未知类型返回原始码）。
func (g GBCode) TypeLabel() string {
	switch g.TypeCode() {
	case TypeVideoChannel:
		return "视频通道"
	case TypeNetworkCamera:
		return "网络摄像机"
	case TypeAlarmIn:
		return "报警输入"
	case TypeAlarmOut:
		return "报警输出"
	case TypeNVR:
		return "硬盘录像机"
	case TypeBusinessGroup:
		return "业务分组"
	case TypeVirtualOrg:
		return "虚拟组织"
	case TypeCascadePlatform:
		return "国标平台"
	}
	if g.IsPlatform() {
		return "平台"
	}
	return g.TypeCode()
}

// IsValid 宽松校验函数（供规则事实使用，不构造值对象）。
func IsValid(code string) bool {
	_, err := Parse(code)
	return err == nil
}
