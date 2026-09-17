package sip

import (
	"fmt"
	"strings"
	"time"
)

// PlatformCheckResult 为平台侧体检结果。
// 模拟摄像头注册到真实上级平台，验证平台合规性。
type PlatformCheckResult struct {
	PlatformAddr   string
	PlatformID     string
	RegisterOK     bool
	RegisterAlg    string
	KeepaliveOK    bool
	CatalogQueryOK bool
	DeviceInfoOK   bool
	InviteOK       bool
	NATDetected    bool
	Issues         []Issue
	Facts          []string
	TS             time.Time
}

// CheckPlatform 平台侧体检：模拟摄像头注册到真实上级平台，验证平台行为合规性。
// 检查项目：
//  1. 平台是否正确发起 401 质询
//  2. 平台是否正确验证鉴权并回 200 OK
//  3. 平台是否发送心跳应答
//  4. 平台是否发送 Catalog 查询
//  5. 平台是否发送 DeviceInfo 查询
//  6. 平台是否发送 INVITE 点播请求
func CheckPlatform(cam *CameraSideRole, serverID string, checkDuration time.Duration) *PlatformCheckResult {
	result := &PlatformCheckResult{
		PlatformAddr: cam.cfg.ServerAddr,
		PlatformID:   serverID,
		TS:           time.Now(),
	}

	if checkDuration == 0 {
		checkDuration = 15 * time.Second
	}

	// 1. 注册
	resp, alg, err := cam.Register()
	if err != nil {
		result.RegisterOK = false
		result.Facts = append(result.Facts, "注册失败: "+err.Error())
		result.Issues = append(result.Issues, Issue{
			RuleID:   "PLAT-REG-FAIL",
			Category: StageRegister,
			Severity: SeverityBlocking,
			Title:    "平台侧注册失败",
			Explain:  fmt.Sprintf("模拟摄像头无法注册到平台: %s", err.Error()),
			Advice:   []string{"检查平台 SIP 服务器地址和端口", "确认平台已启动并监听", "检查鉴权密码是否正确"},
		})
		return result
	}
	result.RegisterOK = resp.StatusCode == 200
	result.RegisterAlg = alg
	result.Facts = append(result.Facts, fmt.Sprintf("注册结果: %d %s (算法=%s)", resp.StatusCode, resp.ReasonPhrase, alg))

	if resp.StatusCode != 200 {
		result.Issues = append(result.Issues, Issue{
			RuleID:   "PLAT-REG-REJECT",
			Category: StageRegister,
			Severity: SeverityBlocking,
			Title:    fmt.Sprintf("平台拒绝注册（%d）", resp.StatusCode),
			Explain:  fmt.Sprintf("平台返回了 %d，可能是密码错误或设备编码不被接受。", resp.StatusCode),
			Advice:   []string{"确认平台鉴权密码", "检查设备国标编码是否在平台白名单中"},
		})
		return result
	}

	// 2. 心跳
	kaResp, err := cam.Keepalive(1)
	if err != nil {
		result.KeepaliveOK = false
		result.Facts = append(result.Facts, "心跳发送失败: "+err.Error())
	} else {
		result.KeepaliveOK = kaResp.StatusCode == 200
		result.Facts = append(result.Facts, fmt.Sprintf("心跳应答: %d", kaResp.StatusCode))
	}

	// 3. 等待平台发起查询（Catalog/DeviceInfo）
	// 启动监听器自动应答
	listener := cam.StartListener()
	if listener != nil {
		receivedCatalog := false
		receivedDeviceInfo := false
		receivedInvite := false

		listener.OnInboundRequest(func(msg *SipMessage, src string) {
			if msg.Method == "MESSAGE" {
				body := msg.BodyText()
				cmdType := strings.ToLower(XMLTagValue(body, "CmdType"))
				switch cmdType {
				case "catalog":
					receivedCatalog = true
				case "deviceinfo":
					receivedDeviceInfo = true
				}
			}
			if msg.Method == "INVITE" {
				receivedInvite = true
			}
		})

		// 等待平台发起查询
		deadline := time.Now().Add(checkDuration)
		for time.Now().Before(deadline) {
			if receivedCatalog && receivedDeviceInfo {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}

		result.CatalogQueryOK = receivedCatalog
		result.DeviceInfoOK = receivedDeviceInfo
		result.InviteOK = receivedInvite

		if receivedCatalog {
			result.Facts = append(result.Facts, "平台发送了 Catalog 查询 ✅")
		} else {
			result.Facts = append(result.Facts, "平台未发送 Catalog 查询")
			result.Issues = append(result.Issues, Issue{
				RuleID:   "PLAT-NO-CATALOG",
				Category: StageCatalog,
				Severity: SeverityWarning,
				Title:    "平台未发起 Catalog 查询",
				Explain:  "平台在设备注册后未主动查询设备目录，可能导致设备通道无法在平台侧显示。",
				Advice:   []string{"检查平台是否配置了自动查询目录", "确认设备目录推送开关已打开"},
			})
		}

		if receivedDeviceInfo {
			result.Facts = append(result.Facts, "平台发送了 DeviceInfo 查询 ✅")
		}

		if receivedInvite {
			result.Facts = append(result.Facts, "平台发送了 INVITE 点播请求 ✅")
		}
	}

	// 判定 NAT
	result.NATDetected = false // 简化：实际应比对 Via 与来源地址

	return result
}
