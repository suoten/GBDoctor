// Package diag 实现体检流程引擎（诊断编排层）。
//
// 引擎按环节分段推进：注册→保活→目录→点播→媒体流→时钟，
// 每个环节产出事实 → 规则引擎匹配 → 产出 Issue → 汇总报告。
// 设计铁律（spec 3.4）：
//   1. 故障现象 → 报文证据 → 人话解释 → 修复建议
//   2. 分段推进：注册通了才测目录，目录通了才测点播
//   3. 报告可转发：一页纸说清问题
package diag

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"gbdoctor/internal/rules"
	"gbdoctor/internal/sip"
)

// CheckStage 为体检环节状态。
type CheckStage string

const (
	StageRegister   CheckStage = "register"
	StageKeepalive  CheckStage = "keepalive"
	StageCatalog    CheckStage = "catalog"
	StageInvite     CheckStage = "invite"
	StageRTP        CheckStage = "rtp"
	StageClock      CheckStage = "clock"
	StageDeviceInfo CheckStage = "deviceinfo"
	StagePTZ        CheckStage = "ptz"
	StageAlarm      CheckStage = "alarm"
	StageRecord     CheckStage = "record"
	StageVoice      CheckStage = "voice"
	StageGB2022     CheckStage = "gb2022"
)

// StageResult 为单个环节的检查结果。
type StageResult struct {
	Stage     CheckStage
	Passed    bool
	Skipped   bool // 因前置环节失败而跳过
	Issues    []sip.Issue
	Facts     []string // 人话事实描述
	Evidence  []sip.Evidence
	Duration  time.Duration
	StartTime time.Time
}

// ReportData 为完整体检报告数据。
type ReportData struct {
	ReportID      string
	DeviceID      string
	StartTime     time.Time
	EndTime       time.Time
	TotalDuration time.Duration
	Score         int // 0-100
	Passed        bool
	Stages        []StageResult
	AllIssues     []sip.Issue
	EvidenceCount int
	RuleCount     int
}

// CheckConfig 为体检配置。
type CheckConfig struct {
	DeviceID        string
	ServerAddr      string // 平台地址（模拟摄像头模式用）
	Password        string
	Transport       string // udp/tcp
	CatalogTimeout  time.Duration
	InviteTimeout   time.Duration
	RTPDuration     time.Duration // 接收 RTP 流的持续时间
	KeepaliveWindow time.Duration // 保活观察窗（等待第一包心跳的最长时间）
	SkipCatalog     bool
	SkipInvite      bool
	SkipRTP         bool
	SkipClock       bool
	SkipDeviceInfo  bool
	SkipPTZ         bool
	SkipAlarm       bool
	SkipRecord      bool
	SkipVoice       bool
	SkipGB2022      bool
}

// Engine 为体检引擎。
type Engine struct {
	role           *sip.DeviceSideRole
	ruleEngine     *sip.RuleEngine
	cfg            CheckConfig
	mu             sync.Mutex
	rtpReceiver    *sip.RTPReceiver // RTP 接收器（checkInvite 启动，checkRTP 分析）
	lastInviteSDP  *sip.SDPInfo     // 点播应答 SDP（供 GB2022 检测复用真实数据）
	lastInviteFact *sip.InviteFact
	clockFact      *sip.ClockFact // 设备上报告警中的时间偏差（异步收集）
}

// NewEngine 创建体检引擎。
func NewEngine(role *sip.DeviceSideRole, ruleEngine *sip.RuleEngine, cfg CheckConfig) *Engine {
	return &Engine{
		role:       role,
		ruleEngine: ruleEngine,
		cfg:        cfg,
	}
}

// RuleEngine 返回规则引擎（供批量体检复用）。
func (e *Engine) RuleEngine() *sip.RuleEngine { return e.ruleEngine }

// NewDefaultEngine 创建使用内置规则的体检引擎。
func NewDefaultEngine(role *sip.DeviceSideRole, cfg CheckConfig) (*Engine, error) {
	re, err := rules.NewEngineWithBuiltinRules()
	if err != nil {
		return nil, fmt.Errorf("加载规则引擎失败: %w", err)
	}
	return NewEngine(role, re, cfg), nil
}

// Run 执行全链路体检（分段推进）。
func (e *Engine) Run() *ReportData {
	report := &ReportData{
		ReportID:  fmt.Sprintf("GBD-%s-%04d", time.Now().Format("20060102-150405"), time.Now().UnixNano()%10000),
		DeviceID:  e.cfg.DeviceID,
		StartTime: time.Now(),
	}
	defer func() {
		report.EndTime = time.Now()
		report.TotalDuration = report.EndTime.Sub(report.StartTime)
		report.Score = calculateScore(report)
		report.Passed = report.Score >= 60
		if e.ruleEngine != nil {
			report.RuleCount = e.ruleEngine.RuleCount()
		}
	}()

	// 订阅报警通知：设备上报的 AlarmTime 是链路中唯一的设备时钟来源，
	// 异步收集供时钟环节使用（可注销，防止长驻服务回调无限增长）。
	cancelAlarmSub := e.role.OnAlarm(func(a sip.AlarmFact) {
		if a.AlarmTime == "" {
			return
		}
		cf := sip.CheckClockSync(a.AlarmTime, a.DeviceID)
		if !cf.DeviceTime.IsZero() {
			e.mu.Lock()
			e.clockFact = &cf
			e.mu.Unlock()
		}
	})
	defer cancelAlarmSub()

	// 环节 1：注册
	regResult := e.checkRegister()
	report.Stages = append(report.Stages, *regResult)
	report.AllIssues = append(report.AllIssues, regResult.Issues...)
	if !regResult.Passed {
		// 注册失败，后续所有环节全部跳过（包括 V1.1/V1.2 环节）
		for _, stage := range []CheckStage{
			StageKeepalive, StageCatalog, StageInvite, StageRTP, StageClock,
			StageDeviceInfo, StagePTZ, StageAlarm, StageRecord,
			StageVoice, StageGB2022,
		} {
			report.Stages = append(report.Stages, StageResult{Stage: stage, Skipped: true})
		}
		return report
	}

	// 环节 2：保活
	kaResult := e.checkKeepalive()
	report.Stages = append(report.Stages, *kaResult)
	report.AllIssues = append(report.AllIssues, kaResult.Issues...)

	// 环节 3：目录
	if !e.cfg.SkipCatalog {
		catResult := e.checkCatalog()
		report.Stages = append(report.Stages, *catResult)
		report.AllIssues = append(report.AllIssues, catResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageCatalog, Skipped: true})
	}

	// 环节 4：点播
	if !e.cfg.SkipInvite {
		invResult := e.checkInvite()
		report.Stages = append(report.Stages, *invResult)
		report.AllIssues = append(report.AllIssues, invResult.Issues...)

		// 环节 5：RTP 媒体流（依赖点播成功）
		if invResult.Passed && !e.cfg.SkipRTP {
			rtpResult := e.checkRTP()
			report.Stages = append(report.Stages, *rtpResult)
			report.AllIssues = append(report.AllIssues, rtpResult.Issues...)
		} else {
			report.Stages = append(report.Stages, StageResult{Stage: StageRTP, Skipped: true})
		}
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageInvite, Skipped: true})
		report.Stages = append(report.Stages, StageResult{Stage: StageRTP, Skipped: true})
	}

	// 环节 6：时钟偏差
	if !e.cfg.SkipClock {
		clkResult := e.checkClock()
		report.Stages = append(report.Stages, *clkResult)
		report.AllIssues = append(report.AllIssues, clkResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageClock, Skipped: true})
	}
	// 环节 7：设备信息查询（V1.1）
	if !e.cfg.SkipDeviceInfo {
		diResult := e.checkDeviceInfo()
		report.Stages = append(report.Stages, *diResult)
		report.AllIssues = append(report.AllIssues, diResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageDeviceInfo, Skipped: true})
	}

	// 环节 8：PTZ 控制验证（V1.1）
	if !e.cfg.SkipPTZ {
		ptzResult := e.checkPTZ()
		report.Stages = append(report.Stages, *ptzResult)
		report.AllIssues = append(report.AllIssues, ptzResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StagePTZ, Skipped: true})
	}

	// 环节 9：报警订阅（V1.1）
	if !e.cfg.SkipAlarm {
		almResult := e.checkAlarm()
		report.Stages = append(report.Stages, *almResult)
		report.AllIssues = append(report.AllIssues, almResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageAlarm, Skipped: true})
	}

	// 环节 10：录像检索（V1.1）
	if !e.cfg.SkipRecord {
		recResult := e.checkRecord()
		report.Stages = append(report.Stages, *recResult)
		report.AllIssues = append(report.AllIssues, recResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageRecord, Skipped: true})
	}

	// 环节 11：语音对讲（V1.1）
	if !e.cfg.SkipVoice {
		voiceResult := e.checkVoice()
		report.Stages = append(report.Stages, *voiceResult)
		report.AllIssues = append(report.AllIssues, voiceResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageVoice, Skipped: true})
	}

	// 环节 12：2022 新标检测（V1.2）
	if !e.cfg.SkipGB2022 {
		gbResult := e.checkGB2022()
		report.Stages = append(report.Stages, *gbResult)
		report.AllIssues = append(report.AllIssues, gbResult.Issues...)
	} else {
		report.Stages = append(report.Stages, StageResult{Stage: StageGB2022, Skipped: true})
	}

	// 证据条数
	if e.role != nil {
		report.EvidenceCount = e.role.Evidence().Count()
	}

	return report
}

// checkRegister 检查注册环节。
func (e *Engine) checkRegister() *StageResult {
	result := &StageResult{
		Stage:     StageRegister,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	// 等待注册事实（由外部 simcam 或真机触发）
	// 在体检引擎中，我们检查已有会话
	session, ok := e.role.Session(e.cfg.DeviceID)
	if !ok {
		result.Passed = false
		result.Facts = append(result.Facts, "设备未注册到模拟平台")
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "REG-NO-SESSION",
			Category: sip.StageRegister,
			Severity: sip.SeverityBlocking,
			Title:    "设备未注册",
			Explain:  "设备未注册到模拟平台，无法进行后续检测。",
			Advice:   []string{"检查设备 SIP 配置，确认服务器 IP 和端口正确"},
		})
		return result
	}

	result.Passed = true
	result.Facts = append(result.Facts,
		fmt.Sprintf("设备 %s 已注册（算法=%s, Expires=%d, 注册次数=%d）",
			session.DeviceID, session.Algorithm, session.Expires, session.RegisterCount))

	// 如果有证据，收集
	if e.role.Evidence() != nil {
		for _, ev := range e.role.Evidence().All() {
			if ev.CallID != "" {
				result.Evidence = append(result.Evidence, ev)
			}
		}
	}

	return result
}

// checkKeepalive 检查保活环节。
func (e *Engine) checkKeepalive() *StageResult {
	result := &StageResult{
		Stage:     StageKeepalive,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	session, ok := e.role.Session(e.cfg.DeviceID)
	if !ok {
		result.Passed = false
		return result
	}

	if session.KeepaliveCount == 0 {
		// 保活观察窗：国标设备心跳周期默认 60s，注册后立即检查会把
		// "心跳还没到点" 误报为 "未收到心跳"。等待观察窗后复查。
		window := e.cfg.KeepaliveWindow
		if window == 0 {
			window = 8 * time.Second
		}
		if window > 0 {
			result.Facts = append(result.Facts, fmt.Sprintf("等待心跳观察窗 %s ...", window))
			time.Sleep(window)
			if s, ok2 := e.role.Session(e.cfg.DeviceID); ok2 {
				session = s
			}
		}
	}

	if session.KeepaliveCount == 0 {
		result.Passed = false
		result.Facts = append(result.Facts, "未收到心跳")
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "KA-NO-HEARTBEAT",
			Category: sip.StageKeepalive,
			Severity: sip.SeverityWarning,
			Title:    "未收到设备心跳",
			Explain:  fmt.Sprintf("设备注册成功但观察窗（%s）内未收到心跳。国标要求设备注册后定期发送 Keepalive；若设备心跳周期大于观察窗，可忽略本条。", e.keepaliveWindow()),
			Advice:   []string{"检查设备心跳周期配置", "确认设备心跳功能已启用", "如设备心跳周期大于 60s，建议核对平台侧心跳超时时间"},
		})
		return result
	}

	result.Passed = true
	result.Facts = append(result.Facts,
		fmt.Sprintf("心跳次数=%d, 最后心跳=%s",
			session.KeepaliveCount, session.LastKeepaliveAt.Format("15:04:05")))
	return result
}

// keepaliveWindow 返回保活观察窗配置（含默认值）。
func (e *Engine) keepaliveWindow() time.Duration {
	if e.cfg.KeepaliveWindow == 0 {
		return 8 * time.Second
	}
	return e.cfg.KeepaliveWindow
}

// checkCatalog 检查目录环节。
func (e *Engine) checkCatalog() *StageResult {
	result := &StageResult{
		Stage:     StageCatalog,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	timeout := e.cfg.CatalogTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// 发送目录查询（注册可注销回调，防止长驻服务回调无限增长）
	catalogCh := make(chan sip.CatalogFact, 1)
	cancelCatalog := e.role.OnCatalog(func(f sip.CatalogFact) {
		if f.DeviceID == e.cfg.DeviceID {
			select {
			case catalogCh <- f:
			default:
			}
		}
	})
	defer cancelCatalog()

	if err := e.role.QueryCatalog(e.cfg.DeviceID); err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "发送目录查询失败: "+err.Error())
		return result
	}

	select {
	case fact := <-catalogCh:
		result.Facts = append(result.Facts, fmt.Sprintf("目录查询返回 %d 个通道", len(fact.Items)))
		if e.ruleEngine != nil {
			result.Issues = append(result.Issues, e.ruleEngine.EvaluateCatalog(fact)...)
		}
		// 逐条校验通道编码
		for _, item := range fact.Items {
			devs := sip.CatalogItemValidations(item)
			for _, d := range devs {
				result.Facts = append(result.Facts, d.Detail)
			}
		}
		result.Passed = len(fact.Items) > 0 && fact.ErrCode == ""
		if len(fact.Items) == 0 {
			result.Issues = append(result.Issues, sip.Issue{
				RuleID:   "CAT-NO-ITEMS",
				Category: sip.StageCatalog,
				Severity: sip.SeverityBlocking,
				Title:    "目录为空",
				Explain:  "设备返回的目录为空，可能未配置通道或目录推送未开启。",
				Advice:   []string{"检查设备目录推送配置", "确认设备已配置视频通道"},
			})
		}
	case <-time.After(timeout):
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("目录查询超时（%s）", timeout))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "CAT-TIMEOUT",
			Category: sip.StageCatalog,
			Severity: sip.SeverityBlocking,
			Title:    "目录查询超时",
			Explain:  "设备未在规定时间内响应目录查询。",
			Advice:   []string{"检查设备是否支持 Catalog 查询", "确认设备目录推送功能已开启"},
		})
	}

	return result
}

// checkInvite 检查点播环节。
func (e *Engine) checkInvite() *StageResult {
	result := &StageResult{
		Stage:     StageInvite,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	// 生成 SSRC（10 位数字，前 1 位 0=实时）
	ssrc := "0" + fmt.Sprintf("%09d", time.Now().UnixNano()%1000000000)

	// 在发送 INVITE 前先启动 RTP 接收器。
	// 端口由操作系统分配（bind :0）：随机端口在批量体检/与其他服务冲突时
	// 绑定失败会导致设备向死端口推流，产出误导性的“无 RTP 流”结论。
	e.rtpReceiver = sip.NewRTPReceiver(0)
	if err := e.rtpReceiver.Start(); err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "RTP 接收器启动失败（本机端口被占用或被安全软件拦截）: "+err.Error())
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "RTP-NO-RECEIVER",
			Category: sip.StageRTP,
			Severity: sip.SeverityBlocking,
			Title:    "本机 RTP 接收端口绑定失败",
			Explain:  "无法在本机绑定 RTP 接收端口，诊断端自身环境问题，与摄像头无关。",
			Advice:   []string{"检查本机防火墙/安全软件是否拦截 UDP 端口", "确认本机端口资源未被耗尽"},
		})
		return result
	}
	mediaPort := e.rtpReceiver.LocalPort()
	result.Facts = append(result.Facts, fmt.Sprintf("RTP 接收器已启动，监听端口 %d", mediaPort))

	resp, err := e.role.SendInvite(e.cfg.DeviceID, e.cfg.DeviceID, mediaPort, ssrc)
	if err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "INVITE 发送失败: "+err.Error())
		if e.rtpReceiver != nil {
			e.rtpReceiver.Stop()
		}
		return result
	}

	if resp.StatusCode != 200 {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("INVITE 被拒绝: %d %s", resp.StatusCode, resp.ReasonPhrase))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "INV-REJECTED",
			Category: sip.StageInvite,
			Severity: sip.SeverityBlocking,
			Title:    fmt.Sprintf("INVITE 被拒绝（%d）", resp.StatusCode),
			Explain:  fmt.Sprintf("设备拒绝了点播请求，状态码 %d。", resp.StatusCode),
			Advice:   []string{"检查设备是否支持该通道的点播", "确认设备资源是否充足"},
		})
		if e.rtpReceiver != nil {
			e.rtpReceiver.Stop()
		}
		return result
	}

	// 解析 SDP
	fact := sip.InviteFactFromResponse(resp, e.cfg.DeviceID)
	e.mu.Lock()
	e.lastInviteFact = &fact
	e.lastInviteSDP = fact.SDP
	e.mu.Unlock()
	if fact.SDP != nil {
		result.Facts = append(result.Facts,
			fmt.Sprintf("SDP: 媒体=%s, 端口=%d, SSRC=%s, IP=%s",
				fact.SDP.MediaType, fact.SDP.Port, fact.SDP.SSRC, fact.SDP.IPAddress))
	}

	// SDP 校验
	if fact.SDP != nil {
		devs := sip.SDPValidations(fact.SDP)
		if e.ruleEngine != nil {
			result.Issues = append(result.Issues, e.ruleEngine.EvaluateSDP(devs, fact.SDP)...)
		}
		// 点播环节通过条件：收到 200 OK 且 SDP 有效（有端口、有 SSRC、有媒体类型）
		// 私网 IP 只产生警告 issue，不阻断点播通过
		result.Passed = fact.SDP.Port > 0 && fact.SDP.SSRC != "" && fact.SDP.MediaType != ""
	} else {
		result.Passed = false
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "INV-NO-SDP",
			Category: sip.StageInvite,
			Severity: sip.SeverityBlocking,
			Title:    "200 OK 缺少 SDP",
			Explain:  "设备返回了 200 OK 但未包含 SDP 报文体，平台无法获取媒体流信息。",
			Advice:   []string{"检查设备 SDP 构造是否正确"},
		})
	}

	// 触发 INVITE 事实回调
	e.role.FireInviteFact(fact)

	return result
}

// checkRTP 检查 RTP 媒体流环节。
func (e *Engine) checkRTP() *StageResult {
	result := &StageResult{
		Stage:     StageRTP,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
		if e.rtpReceiver != nil {
			e.rtpReceiver.Stop()
		}
		// 无论成败，挂断点播会话：不发送 BYE 设备会持续推流，
		// 占用编码资源，并导致重复体检因并发流数耗尽被拒（486）产生假故障。
		e.mu.Lock()
		inv := e.lastInviteFact
		e.mu.Unlock()
		if inv != nil && inv.StatusCode == 200 {
			if err := e.role.SendBye(e.cfg.DeviceID, e.cfg.DeviceID); err == nil {
				result.Facts = append(result.Facts, "已发送 BYE 结束点播会话")
			}
		}
	}()

	rtpDuration := e.cfg.RTPDuration
	if rtpDuration == 0 {
		rtpDuration = 5 * time.Second
	}

	result.Facts = append(result.Facts, fmt.Sprintf("RTP 接收持续时间: %s", rtpDuration))

	if e.rtpReceiver == nil {
		result.Passed = false
		result.Facts = append(result.Facts, "RTP 接收器未启动")
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "RTP-NO-RECEIVER",
			Category: sip.StageRTP,
			Severity: sip.SeverityBlocking,
			Title:    "RTP 接收器未启动",
			Explain:  "RTP 接收器未能在 INVITE 环节启动，无法接收媒体流。",
			Advice:   []string{"检查 INVITE 环节是否成功", "确认媒体端口未被占用"},
		})
		return result
	}

	// 等待 RTP 流到达
	time.Sleep(rtpDuration)

	stats := e.rtpReceiver.Stats()
	if stats == nil || stats.TotalPackets == 0 {
		result.Passed = false
		result.Facts = append(result.Facts, "未收到任何 RTP 包")
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "RTP-003-NO-STREAM",
			Category: sip.StageRTP,
			Severity: sip.SeverityBlocking,
			Title:    "INVITE 200 OK 但未收到 RTP 流",
			Explain:  "设备返回了 200 OK 但平台未收到任何 RTP 包。常见原因：SDP 中媒体地址/端口不可达、设备发送方向错误、防火墙拦截了 RTP 端口范围。",
			Advice:   []string{"检查 SDP 中的 IP 和端口是否可达", "确认防火墙放行了 RTP 端口范围（通常 10000-60000 UDP）", "检查设备是否正在推流"},
		})
		return result
	}

	// 分析 RTP 流
	analysis := sip.AnalyzeRTPStream(stats)
	result.Facts = append(result.Facts, sip.RTPToText(analysis))
	result.Facts = append(result.Facts, fmt.Sprintf("总包数: %d, 丢包: %d (%.1f%%), 码率: %.0f kbps",
		stats.TotalPackets, stats.LostPackets, analysis.LossRate, stats.AvgBitRate))

	// 规则引擎匹配
	if e.ruleEngine != nil {
		result.Issues = append(result.Issues, e.ruleEngine.EvaluateRTP(analysis)...)
	}

	// 判定通过条件（收紧：仅收到少量包或码率异常低的流不能算“媒体流正常”）
	if stats.TotalPackets < 20 {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("仅收到 %d 个 RTP 包，不足以确认媒体流正常", stats.TotalPackets))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "RTP-006-SPARSE",
			Category: sip.StageRTP,
			Severity: sip.SeverityBlocking,
			Title:    "RTP 包数过少，疑似空流/黑屏",
			Explain:  fmt.Sprintf("设备有推流动作但包数极少（%d 包），可能为空流、黑屏或码流异常。", stats.TotalPackets),
			Advice:   []string{"确认摄像机镜头未被遮挡、画面非纯黑", "检查设备码流参数配置", "用播放器直接拉流验证画面"},
		})
		return result
	}
	if !analysis.BitRateOK {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("平均码率 %.0f kbps 低于 64 kbps，疑似空流", stats.AvgBitRate))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "RTP-007-LOW-BITRATE",
			Category: sip.StageRTP,
			Severity: sip.SeverityBlocking,
			Title:    "媒体流码率异常过低",
			Explain:  fmt.Sprintf("收到 RTP 流但平均码率仅 %.0f kbps，正常视频流至少 64 kbps 以上，可能为空流或黑屏。", stats.AvgBitRate),
			Advice:   []string{"确认摄像机画面非纯黑/遮挡", "检查设备码率配置"},
		})
		return result
	}
	result.Passed = !analysis.IsScreenCorrupt

	return result
}

// checkClock 检查时钟偏差环节。
// 国标链路本身没有“查询设备当前时间”的指令；设备时间只能从其主动上报的
// 通知（如报警 AlarmTime）中获取。若本此体检期间设备未上报时间，本环节
// 诚实标记为“无法检测”，绝不产出假通过/假失败。
func (e *Engine) checkClock() *StageResult {
	result := &StageResult{
		Stage:     StageClock,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	e.mu.Lock()
	cf := e.clockFact
	e.mu.Unlock()

	if cf == nil || cf.DeviceTime.IsZero() {
		result.Skipped = true
		result.Facts = append(result.Facts, "本链路未获取到设备上报的时间字段（国标无时间查询指令），无法自动校验时钟")
		result.Facts = append(result.Facts, "建议：在设备上配置 NTP 服务器并人工核对时间；如设备支持报警上报，可触发一次报警后重新体检")
		return result
	}

	result.Facts = append(result.Facts,
		fmt.Sprintf("设备上报时间=%s，平台时间=%s",
			cf.DeviceTime.Format("2006-01-02 15:04:05"),
			cf.PlatformTime.Format("2006-01-02 15:04:05")))
	result.Facts = append(result.Facts, sip.ClockOffsetConclusions(cf.Offset)...)

	abs := cf.Offset
	if abs < 0 {
		abs = -abs
	}
	if abs > 300*time.Second {
		result.Passed = false
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "CLK-001-LARGE-OFFSET",
			Category: sip.StageClock,
			Severity: sip.SeverityWarning,
			Title:    "设备时钟偏差过大",
			Explain:  fmt.Sprintf("设备上报时间与平台时间偏差 %s，超过国标 300s 要求，可能导致注册异常/录像时间错乱", cf.Offset),
			Advice:   []string{"在设备上配置 NTP 服务器", "手动校准设备时间"},
		})
	} else {
		result.Passed = true
	}
	return result
}

// checkDeviceInfo 检查设备信息查询环节（V1.1）。
func (e *Engine) checkDeviceInfo() *StageResult {
	result := &StageResult{
		Stage:     StageDeviceInfo,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	timeout := 10 * time.Second
	diCh := make(chan sip.DeviceInfoFact, 1)
	cancelDI := e.role.OnDeviceInfo(func(f sip.DeviceInfoFact) {
		if f.DeviceID == e.cfg.DeviceID {
			select {
			case diCh <- f:
			default:
			}
		}
	})
	defer cancelDI()

	if err := e.role.QueryDeviceInfo(e.cfg.DeviceID); err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "发送 DeviceInfo 查询失败: "+err.Error())
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "DEV-NO-QUERY",
			Category: sip.StageDeviceInfo,
			Severity: sip.SeverityWarning,
			Title:    "DeviceInfo 查询发送失败",
			Explain:  fmt.Sprintf("发送 DeviceInfo 查询报文失败: %s", err.Error()),
			Advice:   []string{"确认设备已注册", "检查传输层连接"},
		})
		return result
	}

	select {
	case fact := <-diCh:
		result.Facts = append(result.Facts,
			fmt.Sprintf("厂商=%s, 型号=%s, 固件=%s", fact.Manufacturer, fact.Model, fact.Firmware))
		if fact.Manufacturer == "" && fact.Model == "" {
			result.Passed = false
			result.Issues = append(result.Issues, sip.Issue{
				RuleID:   "DEV-001-NO-RESPONSE",
				Category: sip.StageDeviceInfo,
				Severity: sip.SeverityWarning,
				Title:    "DeviceInfo 应答内容为空",
				Explain:  "设备返回了 DeviceInfo 应答但关键字段（厂商、型号）为空。",
				Advice:   []string{"检查设备固件是否支持 DeviceInfo 查询", "确认设备能力集"},
			})
		} else {
			result.Passed = true
		}
	case <-time.After(timeout):
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("DeviceInfo 查询超时（%s）", timeout))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "DEV-001-NO-RESPONSE",
			Category: sip.StageDeviceInfo,
			Severity: sip.SeverityWarning,
			Title:    "DeviceInfo 查询无应答",
			Explain:  "设备未在规定时间内响应 DeviceInfo 查询。部分老设备不支持该查询类型。",
			Advice:   []string{"检查设备固件版本是否支持 DeviceInfo 查询", "确认设备能力集是否包含该功能"},
		})
	}

	return result
}

// checkPTZ 检查 PTZ 控制环节（V1.1）。
func (e *Engine) checkPTZ() *StageResult {
	result := &StageResult{
		Stage:     StagePTZ,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	// 发送一个安全的无操作 PTZ 指令（停止指令：A50F0100000000B1，不会实际改变云台状态），
	// 并等待设备 200 OK：设备对 DeviceControl MESSAGE 的应答是 PTZ 通道
	// 是否可达/被接受的唯一权威证据，仅看“报文已发出”会产出假通过。
	ptzCmd := "A50F0100000000B1"
	resp, err := e.role.PTZControlWait(e.cfg.DeviceID, e.cfg.DeviceID, ptzCmd, 5*time.Second)
	if err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "PTZ 控制未收到设备应答: "+err.Error())
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "PTZ-001-NO-RESPONSE",
			Category: sip.StagePTZ,
			Severity: sip.SeverityWarning,
			Title:    "PTZ 指令无应答",
			Explain:  "发送 PTZ 控制指令后设备未在 5 秒内回 200 OK。固定枪机不支持云台属正常现象；球机/半球机不应出现。",
			Advice:   []string{"确认设备是否为云台设备（固定枪机不支持 PTZ 属正常）", "检查设备 PTZ 功能是否启用"},
		})
		return result
	}
	if resp.StatusCode != 200 {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("PTZ 指令被拒绝: %d %s", resp.StatusCode, resp.ReasonPhrase))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "PTZ-002-REJECTED",
			Category: sip.StagePTZ,
			Severity: sip.SeverityWarning,
			Title:    fmt.Sprintf("PTZ 指令被拒绝（%d）", resp.StatusCode),
			Explain:  "设备明确拒绝了 PTZ 控制指令。",
			Advice:   []string{"确认设备是否为云台设备", "检查设备 PTZ 权限配置"},
		})
		return result
	}

	result.Passed = true
	result.Facts = append(result.Facts, fmt.Sprintf("PTZ 控制指令已发送并获设备确认: %s", ptzCmd))

	return result
}

// checkAlarm 检查报警订阅环节（V1.1）。
func (e *Engine) checkAlarm() *StageResult {
	result := &StageResult{
		Stage:     StageAlarm,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	// 等待设备对订阅请求的 200 OK：订阅被接受才算建立。
	resp, err := e.role.SubscribeAlarmWait(e.cfg.DeviceID, 60, 5*time.Second)
	if err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "报警订阅未收到设备应答: "+err.Error())
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "ALM-001-SUBSCRIBE-FAIL",
			Category: sip.StageAlarm,
			Severity: sip.SeverityWarning,
			Title:    "报警订阅无应答",
			Explain:  "发送报警订阅后设备未在 5 秒内回 200 OK，订阅未建立，平台可能收不到报警事件。",
			Advice:   []string{"检查设备报警订阅/事件上报功能是否启用", "部分老设备不支持报警订阅"},
		})
		return result
	}
	if resp.StatusCode != 200 {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("报警订阅被拒绝: %d %s", resp.StatusCode, resp.ReasonPhrase))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "ALM-002-REJECTED",
			Category: sip.StageAlarm,
			Severity: sip.SeverityWarning,
			Title:    fmt.Sprintf("报警订阅被拒绝（%d）", resp.StatusCode),
			Explain:  "设备明确拒绝了报警订阅请求。",
			Advice:   []string{"检查设备报警订阅功能配置"},
		})
		return result
	}

	result.Passed = true
	result.Facts = append(result.Facts, "报警订阅请求已发送并获设备确认（Expires=60s）")

	return result
}

// checkRecord 检查录像检索环节（V1.1）。
func (e *Engine) checkRecord() *StageResult {
	result := &StageResult{
		Stage:     StageRecord,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	timeout := 10 * time.Second
	recCh := make(chan sip.RecordInfoFact, 1)
	cancelRec := e.role.OnRecordInfo(func(f sip.RecordInfoFact) {
		if f.DeviceID == e.cfg.DeviceID {
			select {
			case recCh <- f:
			default:
			}
		}
	})
	defer cancelRec()

	// 查询最近 24 小时的录像
	endTime := time.Now().Format("2006-01-02 15:04:05")
	startTime := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	if err := e.role.QueryRecordInfo(e.cfg.DeviceID, startTime, endTime); err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "录像检索发送失败: "+err.Error())
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "REC-001-NO-QUERY",
			Category: sip.StageRecord,
			Severity: sip.SeverityAdvice,
			Title:    "录像检索发送失败",
			Explain:  fmt.Sprintf("发送录像检索报文失败: %s", err.Error()),
			Advice:   []string{"确认设备已注册", "检查传输层连接"},
		})
		return result
	}

	select {
	case fact := <-recCh:
		result.Facts = append(result.Facts, fmt.Sprintf("录像检索返回 %d 条记录", len(fact.Items)))
		if len(fact.Items) == 0 {
			result.Passed = true // 无录像不算失败
			result.Issues = append(result.Issues, sip.Issue{
				RuleID:   "REC-001-NO-RECORD",
				Category: sip.StageRecord,
				Severity: sip.SeverityAdvice,
				Title:    "录像检索无结果",
				Explain:  "在指定时间范围内未检索到录像。可能是设备未开启录像，或时间范围选择错误。",
				Advice:   []string{"确认设备录像计划配置", "检查检索时间范围是否包含录像时间段", "确认设备存储介质正常"},
			})
		} else {
			result.Passed = true
		}
	case <-time.After(timeout):
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("录像检索超时（%s）", timeout))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "REC-001-TIMEOUT",
			Category: sip.StageRecord,
			Severity: sip.SeverityWarning,
			Title:    "录像检索超时",
			Explain:  "设备未在规定时间内响应录像检索查询。",
			Advice:   []string{"检查设备是否支持 RecordInfo 查询", "确认设备录像功能已开启"},
		})
	}

	return result
}

// checkVoice 检查语音对讲环节（V1.1）。
func (e *Engine) checkVoice() *StageResult {
	result := &StageResult{
		Stage:     StageVoice,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	ssrc := "0" + fmt.Sprintf("%09d", time.Now().UnixNano()%1000000000)
	mediaPort := 12000 + int(time.Now().UnixNano()%1000)

	resp, err := e.role.SendVoiceInvite(e.cfg.DeviceID, e.cfg.DeviceID, mediaPort, ssrc)
	if err != nil {
		result.Passed = false
		result.Facts = append(result.Facts, "语音对讲 INVITE 发送失败: "+err.Error())
		return result
	}

	if resp.StatusCode != 200 {
		result.Passed = false
		result.Facts = append(result.Facts, fmt.Sprintf("语音对讲被拒绝: %d", resp.StatusCode))
		result.Issues = append(result.Issues, sip.Issue{
			RuleID:   "VOICE-001-REJECT",
			Category: sip.StageVoice,
			Severity: sip.SeverityWarning,
			Title:    fmt.Sprintf("语音对讲被拒绝（%d）", resp.StatusCode),
			Explain:  "设备拒绝了语音对讲请求。部分设备不支持语音对讲功能。",
			Advice:   []string{"确认设备支持语音对讲", "检查音频通道配置"},
		})
		return result
	}

	// 解析语音对讲 SDP
	fact := sip.VoiceFactFromResponse(resp, e.cfg.DeviceID)
	if fact.SDP != nil {
		result.Facts = append(result.Facts,
			fmt.Sprintf("语音 SDP: 媒体=%s, 端口=%d, 方向=%s",
				fact.SDP.MediaType, fact.SDP.Port, fact.Direction))
	}

	// SDP 校验
	devs := sip.VoiceValidations(fact.SDP)
	if len(devs) == 0 {
		result.Passed = true
		result.Facts = append(result.Facts, "语音对讲协商成功 ✅")
	} else {
		result.Passed = len(devs) == 0
		for _, d := range devs {
			result.Facts = append(result.Facts, d.Detail)
		}
	}

	return result
}

// checkGB2022 检查 2022 新标合规性（V1.2）。
func (e *Engine) checkGB2022() *StageResult {
	result := &StageResult{
		Stage:     StageGB2022,
		StartTime: time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartTime)
	}()

	// 用注册环节的真实声明算法 + 点播环节的真实 SDP 检测 2022 新标能力。
	session, ok := e.role.Session(e.cfg.DeviceID)
	if !ok {
		result.Passed = false
		result.Facts = append(result.Facts, "设备未注册，无法检测 2022 新标")
		return result
	}

	// session.Algorithm 是设备在鉴权中实际声明并验证通过的算法
	regFact := sip.RegisterFact{
		DeviceID:    e.cfg.DeviceID,
		Algorithm:   session.Algorithm,
		DeclaredAlg: session.Algorithm,
	}

	e.mu.Lock()
	sdp := e.lastInviteSDP
	e.mu.Unlock()
	if sdp == nil {
		result.Facts = append(result.Facts, "点播未成功，SM4/TLS 等 SDP 加密能力未能检测")
	}

	// 执行 2022 新标检测
	gbResult := sip.CheckGB2022(regFact, sdp)

	// 2022 新标为建议/警告级合规性探测，不作为阻断判据
	result.Passed = true
	for _, fact := range gbResult.Facts {
		result.Facts = append(result.Facts, fact)
	}
	result.Issues = append(result.Issues, gbResult.Issues...)

	return result
}

// calculateScore 根据环节结果计算体检得分。
func calculateScore(report *ReportData) int {
	if len(report.Stages) == 0 {
		return 0
	}
	totalStages := 0
	passedStages := 0
	blockingIssues := 0
	warningIssues := 0
	adviceIssues := 0

	for _, s := range report.Stages {
		if s.Skipped {
			continue
		}
		totalStages++
		if s.Passed {
			passedStages++
		}
		for _, iss := range s.Issues {
			switch iss.Severity {
			case sip.SeverityBlocking:
				blockingIssues++
			case sip.SeverityWarning:
				warningIssues++
			case sip.SeverityAdvice:
				adviceIssues++
			}
		}
	}

	if totalStages == 0 {
		return 0
	}

	baseScore := passedStages * 100 / totalStages
	penalty := blockingIssues*15 + warningIssues*5 + adviceIssues*1
	score := baseScore - penalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// StageProgress 返回环节进度条（HTML 格式）。
func StageProgress(report *ReportData) string {
	var icons string
	stageOrder := []CheckStage{StageRegister, StageKeepalive, StageCatalog, StageInvite, StageRTP, StageClock, StageDeviceInfo, StagePTZ, StageAlarm, StageRecord, StageVoice, StageGB2022}
	stageLabels := map[CheckStage]string{
		StageRegister:   "注册",
		StageKeepalive:  "保活",
		StageCatalog:    "目录",
		StageInvite:     "点播",
		StageRTP:        "媒体流",
		StageClock:      "时钟",
		StageDeviceInfo: "设备信息",
		StagePTZ:        "云台",
		StageAlarm:      "报警",
		StageRecord:     "录像",
		StageVoice:      "语音",
		StageGB2022:     "2022新标",
	}

	for _, stage := range stageOrder {
		var found *StageResult
		for i := range report.Stages {
			if report.Stages[i].Stage == stage {
				found = &report.Stages[i]
				break
			}
		}
		if found == nil {
			icons += "○"
			continue
		}
		if found.Skipped {
			icons += "○"
		} else if found.Passed {
			icons += "●"
		} else {
			icons += "✗"
		}
		_ = stageLabels
	}
	return icons
}

// SeverityLabel 返回严重程度的中文标签。
func SeverityLabel(s sip.Severity) string {
	switch s {
	case sip.SeverityBlocking:
		return "阻断级"
	case sip.SeverityWarning:
		return "警告级"
	case sip.SeverityAdvice:
		return "建议级"
	}
	return string(s)
}

// ScoreLabel 返回得分的文字标签。
func ScoreLabel(score int) string {
	if score >= 80 {
		return "✅ 通过"
	}
	if score >= 60 {
		return "⚠️ 基本通过"
	}
	return "❌ 不通过"
}

// FormatDuration 格式化持续时间。
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return strconv.Itoa(int(d.Milliseconds())) + "ms"
	}
	return strconv.Itoa(int(d.Seconds())) + "s"
}
