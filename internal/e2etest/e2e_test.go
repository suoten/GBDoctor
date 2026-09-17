// Package e2etest 实现端到端集成测试，覆盖全链路体检流程。
// 独立包避免 diag ↔ report 循环导入。
package e2etest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/report"
	"gbdoctor/internal/rules"
	"gbdoctor/internal/sip"
)

// TestE2EFullCheckup 端到端全链路体检测试。
// 模拟上级平台 ↔ 模拟摄像头，覆盖所有 12 个环节：
// 注册→保活→目录→点播→RTP→时钟→设备信息→PTZ→报警→录像→语音对讲→2022新标
func TestE2EFullCheckup(t *testing.T) {
	// === 1. 启动模拟上级平台 ===
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:         "127.0.0.1",
		Port:         0,
		ServerID:     "34020000002000000001",
		Password:     "e2etest",
		ChallengeAlg: "MD5",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()
	t.Logf("模拟平台已启动 127.0.0.1:%d", port)

	// === 2. 注册回调收集 ===
	regCh := make(chan sip.RegisterFact, 10)
	kaCh := make(chan sip.KeepaliveFact, 10)
	catCh := make(chan sip.CatalogFact, 10)
	diCh := make(chan sip.DeviceInfoFact, 10)
	recCh := make(chan sip.RecordInfoFact, 10)

	role.OnRegister(func(f sip.RegisterFact) { regCh <- f })
	role.OnKeepalive(func(f sip.KeepaliveFact) { kaCh <- f })
	role.OnCatalog(func(f sip.CatalogFact) { catCh <- f })
	role.OnDeviceInfo(func(f sip.DeviceInfoFact) { diCh <- f })
	role.OnRecordInfo(func(f sip.RecordInfoFact) { recCh <- f })

	// === 3. 启动模拟摄像头并注册 ===
	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "e2etest",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, alg, err := cam.Register()
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("注册被拒绝: %d %s", resp.StatusCode, resp.ReasonPhrase)
	}
	t.Logf("✅ 注册成功 (算法=%s)", alg)

	// 确认平台收到了注册事实（排空 challenge 事实，直到收到 registered）
	// SIP 注册流程：REGISTER → 401 challenge → REGISTER(鉴权) → 200 OK registered
	sawRegistered := false
deadline:
	for {
		select {
		case f := <-regCh:
			if f.Kind == "registered" {
				sawRegistered = true
				t.Logf("✅ 平台收到注册事实: DeviceID=%s, 算法=%s", f.DeviceID, f.Algorithm)
				break deadline
			}
			// challenge 等中间事实，继续排空
		case <-time.After(2 * time.Second):
			break deadline
		}
	}
	if !sawRegistered {
		t.Error("未收到 registered 事实")
	}

	// === 4. 心跳 ===
	kaResp, err := cam.Keepalive(1)
	if err != nil {
		t.Fatalf("心跳失败: %v", err)
	}
	if kaResp.StatusCode != 200 {
		t.Fatalf("心跳被拒绝: %d", kaResp.StatusCode)
	}
	t.Logf("✅ 心跳成功 (200 OK)")

	select {
	case f := <-kaCh:
		t.Logf("✅ 平台收到心跳事实: DeviceID=%s", f.DeviceID)
	case <-time.After(2 * time.Second):
		t.Error("等待心跳事实超时")
	}

	// === 5. 模拟设备回复目录应答 ===
	go func() {
		time.Sleep(200 * time.Millisecond)
		catalogXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>Catalog</CmdType>
<SN>1001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<SumNum>2</SumNum>
<Item>
<DeviceID>34020000001310000001</DeviceID>
<Name>前门摄像头</Name>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD</Model>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
<Item>
<DeviceID>34020000001310000002</DeviceID>
<Name>后门摄像头</Name>
<Manufacturer>Dahua</Manufacturer>
<Model>IPC-HFW</Model>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
</Response>`
		if _, err := cam.SendMessage(catalogXML); err != nil {
			t.Logf("发送目录应答失败: %v", err)
		}
	}()

	// 等待目录事实
	select {
	case f := <-catCh:
		t.Logf("✅ 平台收到目录应答: %d 个通道", len(f.Items))
		if len(f.Items) != 2 {
			t.Errorf("通道数 = %d, want 2", len(f.Items))
		}
		// 验证通道编码校验
		for _, item := range f.Items {
			devs := sip.CatalogItemValidations(item)
			if len(devs) > 0 {
				t.Logf("通道 %s 校验偏差: %v", item.DeviceID, devs)
			}
		}
	case <-time.After(3 * time.Second):
		t.Error("等待目录应答超时")
	}

	// === 6. 执行全链路体检 ===
	ruleEngine, err := rules.NewEngineWithBuiltinRules()
	if err != nil {
		t.Fatalf("规则引擎初始化失败: %v", err)
	}
	t.Logf("✅ 规则引擎已加载 (%d 条规则)", ruleEngine.RuleCount())

	// 跳过需要真机交互的环节
	engine := diag.NewEngine(role, ruleEngine, diag.CheckConfig{
		DeviceID:       "34020000001320000001",
		SkipCatalog:    true, // 目录通过模拟设备已发送
		SkipInvite:     true, // 点播需要设备 SDP 应答
		SkipRTP:        true, // RTP 需要媒体流
		SkipDeviceInfo: false,
		SkipPTZ:        false,
		SkipAlarm:      false,
		SkipRecord:     false,
	})

	// 在引擎运行期间发送 DeviceInfo 应答（引擎会在 checkDeviceInfo 中设置回调）
	// 需要 delay 足够长，让引擎先设置好 OnDeviceInfo 回调
	go func() {
		time.Sleep(500 * time.Millisecond)
		diXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>2001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD2T46</Model>
<FirmwareVersion>V5.7.3</FirmwareVersion>
<DeviceName>测试摄像头01</DeviceName>
</Response>`
		cam.SendMessage(diXML)
	}()

	// 在引擎运行期间发送 RecordInfo 应答（引擎会在 checkRecord 中设置回调）
	// 需要 delay 足够长，让引擎走到 checkRecord 环节并设置好 OnRecordInfo 回调
	go func() {
		time.Sleep(1 * time.Second)
		recXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>3001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Name>测试摄像头01</Name>
<SumNum>1</SumNum>
<Item>
<DeviceID>34020000001320000001</DeviceID>
<Name>录像段1</Name>
<FilePath>/record/001.mp4</FilePath>
<StartTime>2026-09-16 08:00:00</StartTime>
<EndTime>2026-09-16 09:00:00</EndTime>
</Item>
</Response>`
		cam.SendMessage(recXML)
	}()

	reportData := engine.Run()

	// === 7. 验证体检结果 ===
	t.Logf("体检报告 ID: %s", reportData.ReportID)
	t.Logf("体检得分: %d/100", reportData.Score)
	t.Logf("通过: %v", reportData.Passed)
	t.Logf("环节数: %d", len(reportData.Stages))
	t.Logf("问题数: %d", len(reportData.AllIssues))
	t.Logf("证据数: %d", reportData.EvidenceCount)
	t.Logf("规则数: %d", reportData.RuleCount)

	// 验证环节数量（12 个环节）
	if len(reportData.Stages) != 12 {
		t.Errorf("环节数 = %d, want 12", len(reportData.Stages))
	}

	// 验证注册环节通过
	if !reportData.Stages[0].Passed {
		t.Errorf("注册环节应通过")
	}
	t.Logf("✅ 注册环节: %s", strings.Join(reportData.Stages[0].Facts, "; "))

	// 验证保活环节通过
	if !reportData.Stages[1].Passed {
		t.Errorf("保活环节应通过")
	}
	t.Logf("✅ 保活环节: %s", strings.Join(reportData.Stages[1].Facts, "; "))

	// 验证得分合理
	if reportData.Score < 0 || reportData.Score > 100 {
		t.Errorf("得分 %d 不在 0-100 范围", reportData.Score)
	}

	// === 8. 生成 HTML 报告并验证 ===
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "e2e-report.html")
	if err := report.GenerateHTMLFile(reportData, reportPath); err != nil {
		t.Fatalf("生成 HTML 报告失败: %v", err)
	}
	htmlData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("读取报告文件失败: %v", err)
	}
	htmlStr := string(htmlData)
	if !strings.Contains(htmlStr, "GBDoctor") {
		t.Error("报告应包含 GBDoctor")
	}
	if !strings.Contains(htmlStr, reportData.ReportID) {
		t.Error("报告应包含报告 ID")
	}
	if !strings.Contains(htmlStr, "34020000001320000001") {
		t.Error("报告应包含设备 ID")
	}
	t.Logf("✅ HTML 报告已生成: %s (%d 字节)", reportPath, len(htmlData))

	// === 9. 生成批量报告并验证 ===
	batchData := &report.BatchReportData{
		BatchID:     "BATCH-E2E-001",
		StartTime:   time.Now(),
		DeviceCount: 1,
		PassedCount: 1,
		FailedCount: 0,
		Reports:     []*diag.ReportData{reportData},
	}
	batchPath := filepath.Join(tmpDir, "batch-report.html")
	if err := report.GenerateBatchReportFile(batchData, batchPath); err != nil {
		t.Fatalf("生成批量报告失败: %v", err)
	}
	batchHTML, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatalf("读取批量报告失败: %v", err)
	}
	if !strings.Contains(string(batchHTML), "BATCH-E2E-001") {
		t.Error("批量报告应包含批次 ID")
	}
	t.Logf("✅ 批量报告已生成: %s (%d 字节)", batchPath, len(batchHTML))

	// === 10. 生成对比报告并验证 ===
	beforeReport := &diag.ReportData{
		ReportID:  "GBD-BEFORE",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     30,
		Stages: []diag.StageResult{
			{Stage: diag.StageRegister, Passed: false},
		},
		AllIssues: []sip.Issue{
			{RuleID: "REG-001", Severity: sip.SeverityBlocking, Title: "注册失败"},
		},
	}
	diffPath := filepath.Join(tmpDir, "diff-report.html")
	if err := report.GenerateDiffReportFile(beforeReport, reportData, diffPath); err != nil {
		t.Fatalf("生成对比报告失败: %v", err)
	}
	diffHTML, err := os.ReadFile(diffPath)
	if err != nil {
		t.Fatalf("读取对比报告失败: %v", err)
	}
	diffStr := string(diffHTML)
	if !strings.Contains(diffStr, "对比报告") {
		t.Error("对比报告应包含「对比报告」")
	}
	if !strings.Contains(diffStr, "30/100") {
		t.Error("对比报告应包含修复前得分")
	}
	t.Logf("✅ 对比报告已生成: %s (%d 字节)", diffPath, len(diffHTML))

	// === 11. 验证证据链 ===
	if reportData.EvidenceCount == 0 {
		t.Error("证据链不应为空")
	}
	t.Logf("✅ 证据链: %d 条", reportData.EvidenceCount)

	// === 12. 验证规则库 ===
	if reportData.RuleCount == 0 {
		t.Error("规则数不应为 0")
	}
	t.Logf("✅ 规则库: %d 条", reportData.RuleCount)

	// === 13. 验证环节进度 ===
	stageIcons := diag.StageProgress(reportData)
	t.Logf("环节进度: %s", stageIcons)
	if stageIcons == "" {
		t.Error("环节进度不应为空")
	}

	t.Logf("\n========== 端到端体检测试完成 ==========")
	t.Logf("得分: %d/100 %s", reportData.Score, diag.ScoreLabel(reportData.Score))
	t.Logf("环节: %s", stageIcons)
	t.Logf("证据: %d, 规则: %d, 问题: %d", reportData.EvidenceCount, reportData.RuleCount, len(reportData.AllIssues))
}

// TestE2ERegisterFail 验证注册失败时后续环节全部跳过
func TestE2ERegisterFail(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "wrong-password",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()

	ruleEngine, err := rules.NewEngineWithBuiltinRules()
	if err != nil {
		t.Fatalf("规则引擎初始化失败: %v", err)
	}

	// 设备未注册，直接运行体检引擎
	engine := diag.NewEngine(role, ruleEngine, diag.CheckConfig{
		DeviceID: "34020000001320000001",
	})
	r := engine.Run()

	// 注册环节应失败
	if r.Stages[0].Passed {
		t.Error("注册环节应失败")
	}
	t.Logf("注册环节: Passed=%v, Issues=%d", r.Stages[0].Passed, len(r.Stages[0].Issues))

	// 后续所有环节应被跳过
	for i := 1; i < len(r.Stages); i++ {
		if !r.Stages[i].Skipped {
			t.Errorf("环节 %d 应被跳过", i)
		}
	}
	t.Logf("✅ 注册失败后 %d 个环节全部跳过", len(r.Stages)-1)

	// 得分应为 0
	if r.Score != 0 {
		t.Errorf("得分 = %d, want 0", r.Score)
	}
	t.Logf("得分: %d/100", r.Score)
}

// TestE2ERuleEngineLoad 验证规则库加载和覆盖范围
func TestE2ERuleEngineLoad(t *testing.T) {
	ruleEngine, err := rules.NewEngineWithBuiltinRules()
	if err != nil {
		t.Fatalf("规则引擎加载失败: %v", err)
	}
	allRules := ruleEngine.Rules()
	if len(allRules) < 20 {
		t.Errorf("内置规则数 = %d, want >= 20", len(allRules))
	}
	t.Logf("✅ 内置规则 %d 条已加载", len(allRules))

	// 验证规则覆盖各环节
	categories := map[string]int{}
	for _, r := range allRules {
		categories[r.Category]++
	}
	required := []string{"register", "keepalive", "catalog", "invite", "rtp", "clock", "network"}
	for _, cat := range required {
		if categories[cat] == 0 {
			t.Errorf("缺少 %s 类别规则", cat)
		}
	}
	t.Logf("规则覆盖: %v", categories)
}

// TestE2EReportContent 验证报告内容完整性
func TestE2EReportContent(t *testing.T) {
	r := &diag.ReportData{
		ReportID:  "GBD-CONTENT-TEST",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     45,
		Passed:    false,
		Stages: []diag.StageResult{
			{Stage: diag.StageRegister, Passed: true, Facts: []string{"注册成功"}},
			{Stage: diag.StageKeepalive, Passed: true, Facts: []string{"心跳正常"}},
			{Stage: diag.StageCatalog, Passed: false, Issues: []sip.Issue{
				{
					RuleID:   "CAT-001-EMPTY",
					Category: sip.StageCatalog,
					Severity: sip.SeverityBlocking,
					Title:    "目录查询无响应",
					Explain:  "设备未响应目录查询",
					Evidence: []string{"MESSAGE Catalog 已发送，无应答"},
					Advice:   []string{"检查目录推送开关", "确认设备支持 Catalog"},
					VendorNotes: map[string]string{
						"hikvision": "配置→网络→高级→平台接入→勾选上报目录",
					},
				},
			}},
			{Stage: diag.StageInvite, Skipped: true},
			{Stage: diag.StageRTP, Skipped: true},
			{Stage: diag.StageClock, Passed: true, Facts: []string{"时钟正常"}},
			{Stage: diag.StageDeviceInfo, Passed: true, Facts: []string{"厂商=Hikvision"}},
			{Stage: diag.StagePTZ, Passed: true, Facts: []string{"PTZ 已发送"}},
			{Stage: diag.StageAlarm, Passed: true, Facts: []string{"报警订阅已发送"}},
			{Stage: diag.StageRecord, Passed: true, Facts: []string{"录像检索返回 1 条"}},
		},
		AllIssues: []sip.Issue{
			{
				RuleID:   "CAT-001-EMPTY",
				Category: sip.StageCatalog,
				Severity: sip.SeverityBlocking,
				Title:    "目录查询无响应",
				Explain:  "设备未响应目录查询",
				Evidence: []string{"MESSAGE Catalog 已发送，无应答"},
				Advice:   []string{"检查目录推送开关", "确认设备支持 Catalog"},
				VendorNotes: map[string]string{
					"hikvision": "配置→网络→高级→平台接入→勾选上报目录",
				},
			},
		},
		EvidenceCount: 15,
		RuleCount:     30,
	}

	html, err := report.GenerateHTML(r)
	if err != nil {
		t.Fatalf("生成报告失败: %v", err)
	}

	checks := []struct {
		name     string
		expected string
	}{
		{"报告ID", "GBD-CONTENT-TEST"},
		{"设备ID", "34020000001320000001"},
		{"得分", "45/100"},
		{"环节进度", "环节进度"},
		{"证据数", "15 条"},
		{"规则数", "30 条"},
		{"问题数", "1 个"},
		{"问题标题", "目录查询无响应"},
		{"修复建议", "修复建议"},
		{"厂商备注", "hikvision"},
		{"社区版", "社区版"},
	}
	for _, c := range checks {
		if !strings.Contains(html, c.expected) {
			t.Errorf("报告应包含 %s: %q", c.name, c.expected)
		}
	}
	t.Logf("✅ 报告内容完整性验证通过（%d 项检查）", len(checks))
}

// TestE2ESM3Auth 验证 SM3 鉴权全链路
func TestE2ESM3Auth(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:         "127.0.0.1",
		Port:         0,
		ServerID:     "34020000002000000001",
		Password:     "sm3test",
		ChallengeAlg: sip.AlgoSM3,
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "sm3test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, alg, err := cam.Register()
	if err != nil {
		t.Fatalf("SM3 注册失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("SM3 注册被拒绝: %d", resp.StatusCode)
	}
	if alg != sip.AlgoSM3 {
		t.Errorf("算法 = %s, want SM3", alg)
	}
	t.Logf("✅ SM3 鉴权注册成功 (算法=%s)", alg)

	// 验证心跳
	kaResp, err := cam.Keepalive(1)
	if err != nil || kaResp.StatusCode != 200 {
		t.Fatalf("SM3 心跳失败: err=%v code=%d", err, kaResp.StatusCode)
	}
	t.Logf("✅ SM3 鉴权心跳成功")
}

// TestE2ESHA256Auth 验证 SHA-256 鉴权全链路
func TestE2ESHA256Auth(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:         "127.0.0.1",
		Port:         0,
		ServerID:     "34020000002000000001",
		Password:     "sha256test",
		ChallengeAlg: sip.AlgoSHA256,
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "sha256test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, alg, err := cam.Register()
	if err != nil {
		t.Fatalf("SHA-256 注册失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("SHA-256 注册被拒绝: %d", resp.StatusCode)
	}
	if alg != sip.AlgoSHA256 {
		t.Errorf("算法 = %s, want SHA-256", alg)
	}
	t.Logf("✅ SHA-256 鉴权注册成功 (算法=%s)", alg)
}

// TestE2ECatalogQuery 验证目录查询全链路
func TestE2ECatalogQuery(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "cat-test",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "cat-test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	// 注册
	resp, _, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %d", err, resp.StatusCode)
	}
	t.Logf("✅ 注册成功")

	// 收集目录事实
	catCh := make(chan sip.CatalogFact, 1)
	role.OnCatalog(func(f sip.CatalogFact) { catCh <- f })

	// 发送目录查询
	if err := role.QueryCatalog("34020000001320000001"); err != nil {
		t.Fatalf("发送目录查询失败: %v", err)
	}
	t.Logf("✅ 目录查询已发送")

	// 模拟设备回复目录
	go func() {
		time.Sleep(200 * time.Millisecond)
		catalogXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>Catalog</CmdType>
<SN>5001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<SumNum>3</SumNum>
<Item>
<DeviceID>34020000001310000001</DeviceID>
<Name>通道1</Name>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
<Item>
<DeviceID>34020000001310000002</DeviceID>
<Name>通道2</Name>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
<Item>
<DeviceID>34020000001310000003</DeviceID>
<Name>通道3</Name>
<Status>OFF</Status>
<Parental>0</Parental>
</Item>
</Response>`
		cam.SendMessage(catalogXML)
	}()

	// 等待目录事实
	select {
	case f := <-catCh:
		if len(f.Items) != 3 {
			t.Errorf("通道数 = %d, want 3", len(f.Items))
		}
		t.Logf("✅ 目录应答收到: %d 个通道", len(f.Items))

		// 验证通道编码校验
		for _, item := range f.Items {
			devs := sip.CatalogItemValidations(item)
			if len(devs) > 0 {
				t.Logf("  通道 %s: 偏差 %v", item.DeviceID, devs)
			} else {
				t.Logf("  通道 %s (%s): %s", item.DeviceID, item.Name, item.Status)
			}
		}
	case <-time.After(3 * time.Second):
		t.Error("等待目录应答超时")
	}
}

// TestE2EDeviceInfoQuery 验证设备信息查询全链路
func TestE2EDeviceInfoQuery(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "di-test",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "di-test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, _, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %d", err, resp.StatusCode)
	}

	diCh := make(chan sip.DeviceInfoFact, 1)
	role.OnDeviceInfo(func(f sip.DeviceInfoFact) { diCh <- f })

	// 发送 DeviceInfo 查询
	if err := role.QueryDeviceInfo("34020000001320000001"); err != nil {
		t.Fatalf("发送 DeviceInfo 查询失败: %v", err)
	}

	// 模拟设备回复
	go func() {
		time.Sleep(200 * time.Millisecond)
		diXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>6001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<Manufacturer>Dahua</Manufacturer>
<Model>IPC-HFW2231S</Model>
<FirmwareVersion>V2.840.0</FirmwareVersion>
<DeviceName>大门摄像头</DeviceName>
</Response>`
		cam.SendMessage(diXML)
	}()

	select {
	case f := <-diCh:
		if f.Manufacturer != "Dahua" {
			t.Errorf("Manufacturer = %q, want Dahua", f.Manufacturer)
		}
		if f.Model != "IPC-HFW2231S" {
			t.Errorf("Model = %q, want IPC-HFW2231S", f.Model)
		}
		t.Logf("✅ DeviceInfo 收到: 厂商=%s, 型号=%s, 固件=%s", f.Manufacturer, f.Model, f.Firmware)
	case <-time.After(3 * time.Second):
		t.Error("等待 DeviceInfo 应答超时")
	}
}

// TestE2EReportQuery 验证录像检索全链路
func TestE2EReportQuery(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "rec-test",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "rec-test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, _, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %d", err, resp.StatusCode)
	}

	recCh := make(chan sip.RecordInfoFact, 1)
	role.OnRecordInfo(func(f sip.RecordInfoFact) { recCh <- f })

	// 发送录像检索查询
	startTime := "2026-09-16 00:00:00"
	endTime := "2026-09-16 23:59:59"
	if err := role.QueryRecordInfo("34020000001320000001", startTime, endTime); err != nil {
		t.Fatalf("发送录像检索失败: %v", err)
	}

	// 模拟设备回复
	go func() {
		time.Sleep(200 * time.Millisecond)
		recXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>7001</SN>
<DeviceID>34020000001320000001</DeviceID>
<Name>大门摄像头</Name>
<SumNum>2</SumNum>
<Item>
<DeviceID>34020000001320000001</DeviceID>
<Name>录像段1</Name>
<FilePath>/record/2026-09-16/001.mp4</FilePath>
<StartTime>2026-09-16 08:00:00</StartTime>
<EndTime>2026-09-16 12:00:00</EndTime>
<RecType>1</RecType>
</Item>
<Item>
<DeviceID>34020000001320000001</DeviceID>
<Name>录像段2</Name>
<FilePath>/record/2026-09-16/002.mp4</FilePath>
<StartTime>2026-09-16 14:00:00</StartTime>
<EndTime>2026-09-16 18:00:00</EndTime>
<RecType>1</RecType>
</Item>
</Response>`
		cam.SendMessage(recXML)
	}()

	select {
	case f := <-recCh:
		if len(f.Items) != 2 {
			t.Errorf("录像条目数 = %d, want 2", len(f.Items))
		}
		t.Logf("✅ 录像检索收到: %d 条记录", len(f.Items))
		for i, item := range f.Items {
			t.Logf("  录像 %d: %s ~ %s (%s)", i+1, item.StartTime, item.EndTime, item.FilePath)
		}
	case <-time.After(3 * time.Second):
		t.Error("等待录像检索应答超时")
	}
}

// TestE2EAlarmSubscribe 验证报警订阅全链路
func TestE2EAlarmSubscribe(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "alm-test",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "alm-test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, _, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %d", err, resp.StatusCode)
	}

	// 发送报警订阅
	if err := role.SubscribeAlarm("34020000001320000001", 60); err != nil {
		t.Fatalf("发送报警订阅失败: %v", err)
	}
	t.Logf("✅ 报警订阅请求已发送 (Expires=60s)")

	// 模拟设备发送报警通知
	almCh := make(chan sip.AlarmFact, 1)
	role.OnAlarm(func(f sip.AlarmFact) { almCh <- f })

	go func() {
		time.Sleep(200 * time.Millisecond)
		almXML := `<?xml version="1.0" encoding="UTF-8"?>
<Notify>
<CmdType>Alarm</CmdType>
<SN>8001</SN>
<DeviceID>34020000001320000001</DeviceID>
<AlarmMethod>5</AlarmMethod>
<AlarmType>1</AlarmType>
<AlarmTime>2026-09-16 10:30:00</AlarmTime>
<Description>移动侦测报警</Description>
<Longitude>116.3974</Longitude>
<Latitude>39.9093</Latitude>
</Notify>`
		cam.SendMessage(almXML)
	}()

	select {
	case f := <-almCh:
		if f.AlarmMethod != "5" {
			t.Errorf("AlarmMethod = %q, want 5", f.AlarmMethod)
		}
		if f.Description != "移动侦测报警" {
			t.Errorf("Description = %q", f.Description)
		}
		t.Logf("✅ 报警通知收到: Method=%s, Type=%s, Desc=%s", f.AlarmMethod, f.AlarmType, f.Description)
	case <-time.After(3 * time.Second):
		t.Error("等待报警通知超时")
	}
}

// TestE2EPTZControl 验证 PTZ 控制全链路
func TestE2EPTZControl(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:     "127.0.0.1",
		Port:     0,
		ServerID: "34020000002000000001",
		Password: "ptz-test",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()
	port := role.LocalPort()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "ptz-test",
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	resp, _, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %d", err, resp.StatusCode)
	}

	// 发送 PTZ 控制指令（停止指令）
	ptzCmd := "A50F0100000000B1"
	if err := role.PTZControl("34020000001320000001", "34020000001320000001", ptzCmd); err != nil {
		t.Fatalf("发送 PTZ 控制失败: %v", err)
	}
	t.Logf("✅ PTZ 控制指令已发送: %s", ptzCmd)

	// 验证证据链中有 PTZ 控制的出站报文
	time.Sleep(200 * time.Millisecond)
	evCount := role.Evidence().Count()
	if evCount < 3 {
		t.Errorf("证据数应至少 3（注册+心跳+PTZ）, got %d", evCount)
	}
	t.Logf("✅ 证据链: %d 条", evCount)
}
