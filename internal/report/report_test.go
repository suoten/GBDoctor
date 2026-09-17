package report

import (
	"strings"
	"testing"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/sip"
)

func TestGenerateHTML(t *testing.T) {
	report := &diag.ReportData{
		ReportID:  "GBD-TEST-001",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     75,
		Passed:    true,
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
					Advice:   []string{"检查目录推送开关"},
				},
			}},
		},
		AllIssues: []sip.Issue{
			{
				RuleID:   "CAT-001-EMPTY",
				Category: sip.StageCatalog,
				Severity: sip.SeverityBlocking,
				Title:    "目录查询无响应",
				Explain:  "设备未响应目录查询",
				Advice:   []string{"检查目录推送开关"},
			},
		},
		EvidenceCount: 10,
		RuleCount:     30,
	}

	html, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("GenerateHTML 失败: %v", err)
	}
	if html == "" {
		t.Fatal("HTML 不应为空")
	}
	if !strings.Contains(html, "GBD-TEST-001") {
		t.Error("HTML 应包含报告 ID")
	}
	if !strings.Contains(html, "34020000001320000001") {
		t.Error("HTML 应包含设备 ID")
	}
	if !strings.Contains(html, "75/100") {
		t.Error("HTML 应包含得分")
	}
	if !strings.Contains(html, "目录查询无响应") {
		t.Error("HTML 应包含问题标题")
	}
}

func TestGenerateHTMLNoIssues(t *testing.T) {
	report := &diag.ReportData{
		ReportID:  "GBD-TEST-002",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     100,
		Passed:    true,
		Stages: []diag.StageResult{
			{Stage: diag.StageRegister, Passed: true},
			{Stage: diagKeepalive(), Passed: true},
		},
	}

	html, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("GenerateHTML 失败: %v", err)
	}
	if !strings.Contains(html, "所有检测项通过") {
		t.Error("无问题时应显示「所有检测项通过」")
	}
}

func TestScoreClass(t *testing.T) {
	if scoreClass(85) != "pass" {
		t.Error("85 应为 pass")
	}
	if scoreClass(65) != "warn" {
		t.Error("65 应为 warn")
	}
	if scoreClass(30) != "fail" {
		t.Error("30 应为 fail")
	}
}

func TestSeverityClass(t *testing.T) {
	if severityClass(sip.SeverityBlocking) != "blocking" {
		t.Error("blocking")
	}
	if severityClass(sip.SeverityWarning) != "warning" {
		t.Error("warning")
	}
	if severityClass(sip.SeverityAdvice) != "advice" {
		t.Error("advice")
	}
}

func TestGenerateDiffReport(t *testing.T) {
	before := &diag.ReportData{
		ReportID:  "GBD-BEFORE",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     40,
		Stages:    []diag.StageResult{{Stage: diag.StageRegister, Passed: false}},
		AllIssues: []sip.Issue{
			{RuleID: "REG-001", Severity: sip.SeverityBlocking, Title: "注册失败"},
		},
	}
	after := &diag.ReportData{
		ReportID:  "GBD-AFTER",
		DeviceID:  "34020000001320000001",
		StartTime: time.Now(),
		Score:     90,
		Stages:    []diag.StageResult{{Stage: diag.StageRegister, Passed: true}},
	}

	html, err := GenerateDiffReport(before, after)
	if err != nil {
		t.Fatalf("GenerateDiffReport 失败: %v", err)
	}
	if !strings.Contains(html, "对比报告") {
		t.Error("应包含「对比报告」")
	}
	if !strings.Contains(html, "40/100") {
		t.Error("应包含修复前得分")
	}
	if !strings.Contains(html, "90/100") {
		t.Error("应包含修复后得分")
	}
	if !strings.Contains(html, "50") {
		t.Error("应包含得分提升")
	}
}

func TestGenerateBatchReport(t *testing.T) {
	batch := &BatchReportData{
		BatchID:     "BATCH-TEST-001",
		StartTime:   time.Now(),
		DeviceCount: 5,
		PassedCount: 3,
		FailedCount: 2,
		Reports: []*diag.ReportData{
			{DeviceID: "34020000001320000001", Score: 85, AllIssues: []sip.Issue{}},
			{DeviceID: "34020000001320000002", Score: 30, AllIssues: []sip.Issue{
				{RuleID: "REG-001", Severity: sip.SeverityBlocking, Title: "注册失败"},
			}},
		},
	}

	html, err := GenerateBatchReport(batch)
	if err != nil {
		t.Fatalf("GenerateBatchReport 失败: %v", err)
	}
	if !strings.Contains(html, "BATCH-TEST-001") {
		t.Error("应包含批次 ID")
	}
	if !strings.Contains(html, "34020000001320000001") {
		t.Error("应包含设备 ID")
	}
	if !strings.Contains(html, "60%") {
		t.Error("应包含通过率 60%")
	}
}

func TestHTMLEscape(t *testing.T) {
	input := `<script>alert("xss")</script>`
	escaped := htmlEscape(input)
	if strings.Contains(escaped, "<script>") {
		t.Error("应转义 < 和 >")
	}
	if !strings.Contains(escaped, "&lt;script&gt;") {
		t.Error("应包含转义后的标签")
	}
}

// 辅助函数
func diagKeepalive() diag.CheckStage {
	return diag.StageKeepalive
}
