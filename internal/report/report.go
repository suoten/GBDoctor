// Package report 实现 GBDoctor 诊断报告的 HTML 生成。
//
// 报告是产品的灵魂（spec 6.4）：
//   - 得分制 + 通过/不通过结论
//   - 分段进度条
//   - 证据链（原始报文 + 时间戳）
//   - 人话建议
//   - 可导出 HTML（自包含单文件，可截图）
package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/sip"
)

const reportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GBDoctor 诊断报告 {{.ReportID}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f5f5;padding:20px}
.report{max-width:800px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:24px 32px}
.header h1{font-size:20px;margin-bottom:4px}
.header .meta{font-size:13px;opacity:.85}
.score-section{display:flex;align-items:center;padding:24px 32px;border-bottom:1px solid #e0e0e0}
.score{font-size:36px;font-weight:bold;width:100px;text-align:center}
.score.fail{color:#c62828}
.score.warn{color:#f57f17}
.score.pass{color:#2e7d32}
.score-info{flex:1;margin-left:24px}
.score-info .label{font-size:14px;color:#666}
.score-info .verdict{font-size:18px;font-weight:bold;margin-top:4px}
.progress-section{padding:16px 32px;border-bottom:1px solid #e0e0e0}
.progress-bar{display:flex;align-items:center;gap:4px;font-size:18px}
.progress-bar .stage{display:flex;flex-direction:column;align-items:center;flex:1}
.progress-bar .icon{font-size:20px}
.progress-bar .label{font-size:12px;color:#666;margin-top:4px}
.progress-bar .connector{color:#ccc;font-size:14px}
.issues-section{padding:24px 32px}
.issue{border:1px solid #e0e0e0;border-radius:6px;padding:16px;margin-bottom:12px}
.issue.blocking{border-left:4px solid #c62828}
.issue.warning{border-left:4px solid #f57f17}
.issue.advice{border-left:4px solid #2e7d32}
.issue .title{font-weight:bold;font-size:15px;margin-bottom:8px}
.issue .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;margin-right:8px;color:#fff}
.issue.blocking .badge{background:#c62828}
.issue.warning .badge{background:#f57f17}
.issue.advice .badge{background:#2e7d32}
.issue .explain{font-size:13px;color:#444;margin:8px 0;line-height:1.6}
.issue .evidence{background:#f5f5f5;padding:8px 12px;border-radius:4px;font-family:monospace;font-size:12px;color:#666;margin:8px 0;white-space:pre-wrap;word-break:break-all}
.issue .advice{font-size:13px;color:#333;margin-top:8px}
.issue .advice li{margin-left:20px;margin-bottom:4px}
.issue .vendor{font-size:12px;color:#888;margin-top:8px;padding-top:8px;border-top:1px dashed #e0e0e0}
.footer{padding:16px 32px;background:#fafafa;border-top:1px solid #e0e0e0;text-align:center;font-size:12px;color:#999}
.footer a{color:#1a237e;text-decoration:none}
.summary{padding:16px 32px;background:#f9f9f9;border-bottom:1px solid #e0e0e0;font-size:13px;color:#444}
.summary span{margin-right:16px}
</style>
</head>
<body>
<div class="report">
  <div class="header">
    <h1>GBDoctor 诊断报告 {{.ReportID}}</h1>
    <div class="meta">
      设备: {{.DeviceID}} | 体检时间: {{.StartTimeFormatted}} | 耗时: {{.DurationFormatted}}
    </div>
  </div>

  <div class="score-section">
    <div class="score {{.ScoreClass}}">{{.Score}}/100</div>
    <div class="score-info">
      <div class="label">体检得分</div>
      <div class="verdict">{{.VerdictLabel}}</div>
    </div>
  </div>

  <div class="progress-section">
    <div style="font-size:14px;color:#666;margin-bottom:12px">环节进度</div>
    <div class="progress-bar">
      {{range .StageProgress}}
      <div class="stage">
        <div class="icon">{{.Icon}}</div>
        <div class="label">{{.Label}}</div>
      </div>
      {{end}}
    </div>
  </div>

  <div class="summary">
    <span>📊 证据: {{.EvidenceCount}} 条</span>
    <span>📋 规则: {{.RuleCount}} 条</span>
    <span>⚠️ 问题: {{.IssueCount}} 个</span>
  </div>

  {{if .Issues}}
  <div class="issues-section">
    <div style="font-size:16px;font-weight:bold;margin-bottom:16px">诊断结果</div>
    {{range .Issues}}
    <div class="issue {{.SeverityClass}}">
      <div class="title"><span class="badge">{{.SeverityLabel}}</span>{{.Title}}</div>
      {{if .ExplainHTML}}<div class="explain">{{.ExplainHTML}}</div>{{end}}
      {{if .EvidenceText}}
      <div class="evidence">{{.EvidenceText}}</div>
      {{end}}
      {{if .Advice}}
      <div class="advice">
        <strong>修复建议：</strong>
        <ol>
        {{range .Advice}}<li>{{.}}</li>{{end}}
        </ol>
      </div>
      {{end}}
      {{if .VendorNotes}}
      <div class="vendor">
        {{range $vendor, $path := .VendorNotes}}
        <div>{{$vendor}}: {{$path}}</div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  </div>
  {{else}}
  <div class="issues-section">
    <div style="text-align:center;padding:40px;color:#2e7d32;font-size:18px">
      ✅ 所有检测项通过，未发现问题
    </div>
  </div>
  {{end}}

  <div class="footer">
    本报告由 GBDoctor 生成（社区版）<br>
    3 分钟体检你的设备 → <a href="#">demo.gbdoctor.cn</a>
  </div>
</div>
</body>
</html>`

// ReportIssueData 为模板中的单个问题数据。
type ReportIssueData struct {
	SeverityClass string
	SeverityLabel string
	Title         string
	ExplainHTML   template.HTML
	EvidenceText  string
	Advice        []string
	VendorNotes   map[string]string
}

// StageProgressData 为环节进度条数据。
type StageProgressData struct {
	Icon  string
	Label string
}

// ReportTemplateData 为模板数据。
type ReportTemplateData struct {
	ReportID           string
	DeviceID           string
	StartTimeFormatted string
	DurationFormatted  string
	Score              int
	ScoreClass         string
	VerdictLabel       string
	StageProgress      []StageProgressData
	EvidenceCount      int
	RuleCount          int
	IssueCount         int
	Issues             []ReportIssueData
}

// GenerateHTML 从体检报告数据生成 HTML。
func GenerateHTML(report *diag.ReportData) (string, error) {
	stageLabels := map[diag.CheckStage]string{
		diag.StageRegister:   "注册",
		diag.StageKeepalive:  "保活",
		diag.StageCatalog:    "目录",
		diag.StageInvite:     "点播",
		diag.StageRTP:        "媒体流",
		diag.StageClock:      "时钟",
		diag.StageDeviceInfo: "设备信息",
		diag.StagePTZ:        "云台",
		diag.StageAlarm:      "报警",
		diag.StageRecord:     "录像",
		diag.StageVoice:      "语音",
		diag.StageGB2022:     "2022新标",
	}
	stageOrder := []diag.CheckStage{diag.StageRegister, diag.StageKeepalive, diag.StageCatalog, diag.StageInvite, diag.StageRTP, diag.StageClock, diag.StageDeviceInfo, diag.StagePTZ, diag.StageAlarm, diag.StageRecord, diag.StageVoice, diag.StageGB2022}

	data := ReportTemplateData{
		ReportID:           report.ReportID,
		DeviceID:           report.DeviceID,
		StartTimeFormatted: report.StartTime.Format("2006-01-02 15:04:05"),
		DurationFormatted:  diag.FormatDuration(report.TotalDuration),
		Score:              report.Score,
		ScoreClass:         scoreClass(report.Score),
		VerdictLabel:       diag.ScoreLabel(report.Score),
		EvidenceCount:      report.EvidenceCount,
		RuleCount:          report.RuleCount,
		IssueCount:         len(report.AllIssues),
	}

	for _, stage := range stageOrder {
		icon := "○"
		for _, s := range report.Stages {
			if s.Stage == stage {
				if s.Skipped {
					icon = "○"
				} else if s.Passed {
					icon = "●"
				} else {
					icon = "✗"
				}
				break
			}
		}
		data.StageProgress = append(data.StageProgress, StageProgressData{Icon: icon, Label: stageLabels[stage]})
	}

	for _, iss := range report.AllIssues {
		data.Issues = append(data.Issues, ReportIssueData{
			SeverityClass: severityClass(iss.Severity),
			SeverityLabel: diag.SeverityLabel(iss.Severity),
			Title:         iss.Title,
			ExplainHTML:   templateHTML(iss.Explain),
			EvidenceText:  strings.Join(iss.Evidence, "\n"),
			Advice:        iss.Advice,
			VendorNotes:   iss.VendorNotes,
		})
	}

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return "", fmt.Errorf("模板解析失败: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("模板渲染失败: %w", err)
	}
	return buf.String(), nil
}

// GenerateHTMLFile 生成 HTML 报告并写入文件。
func GenerateHTMLFile(report *diag.ReportData, path string) error {
	html, err := GenerateHTML(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(html), 0644)
}

// GenerateDiffReport 生成对比报告（V1.2 功能）。
func GenerateDiffReport(before, after *diag.ReportData) (string, error) {
	// 对比报告：修复前后两次体检对比
	beforeHTML, err := GenerateHTML(before)
	if err != nil {
		return "", err
	}
	afterHTML, err := GenerateHTML(after)
	if err != nil {
		return "", err
	}

	diff := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>GBDoctor 对比报告</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#f5f5f5;padding:20px}
.diff-container{max-width:1200px;margin:0 auto}
.diff-header{background:#1a237e;color:#fff;padding:20px;border-radius:8px 8px 0 0}
.diff-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
.diff-col h2{text-align:center;padding:8px;background:#e0e0e0;border-radius:4px;margin-bottom:8px;font-size:14px}
.diff-col iframe{width:100%%;border:1px solid #e0e0e0;border-radius:4px;min-height:600px}
.score-comparison{text-align:center;padding:16px;background:#fff;border-radius:4px;margin-bottom:16px}
.score-comparison .scores{font-size:24px;font-weight:bold}
.score-comparison .before{color:#c62828}
.score-comparison .after{color:#2e7d32}
.score-comparison .arrow{margin:0 16px;color:#999}
</style>
</head>
<body>
<div class="diff-container">
  <div class="diff-header">
    <h1>GBDoctor 对比报告</h1>
    <p>设备: %s | 对比时间: %s</p>
  </div>
  <div class="score-comparison">
    <div class="scores">
      <span class="before">修复前: %d/100</span>
      <span class="arrow">→</span>
      <span class="after">修复后: %d/100</span>
    </div>
    <div style="margin-top:8px;color:#666">得分提升 %d 分</div>
  </div>
  <div class="diff-grid">
    <div class="diff-col">
      <h2>修复前</h2>
      <iframe srcdoc="%s"></iframe>
    </div>
    <div class="diff-col">
      <h2>修复后</h2>
      <iframe srcdoc="%s"></iframe>
    </div>
  </div>
</div>
</body>
</html>`, before.DeviceID, time.Now().Format("2006-01-02 15:04:05"),
		before.Score, after.Score, after.Score-before.Score,
		htmlEscape(beforeHTML), htmlEscape(afterHTML))

	return diff, nil
}

// GenerateDiffReportFile 生成对比报告并写入文件。
func GenerateDiffReportFile(before, after *diag.ReportData, path string) error {
	html, err := GenerateDiffReport(before, after)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(html), 0644)
}

// BatchReportData 为批量体检报告数据（V1.2 功能）。
type BatchReportData struct {
	BatchID     string
	StartTime   time.Time
	DeviceCount int
	PassedCount int
	FailedCount int
	Reports     []*diag.ReportData
}

// GenerateBatchReport 生成批量体检汇总报告（V1.2 功能）。
func GenerateBatchReport(batch *BatchReportData) (string, error) {
	passRate := 0
	if batch.DeviceCount > 0 {
		passRate = batch.PassedCount * 100 / batch.DeviceCount
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>GBDoctor 批量体检报告</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#f5f5f5;padding:20px}
.batch-report{max-width:1000px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.batch-header{background:#1a237e;color:#fff;padding:24px 32px}
.batch-header h1{font-size:20px;margin-bottom:4px}
.batch-summary{padding:24px 32px;border-bottom:1px solid #e0e0e0}
.batch-summary .stats{display:flex;gap:32px}
.batch-summary .stat{text-align:center}
.batch-summary .stat .num{font-size:28px;font-weight:bold}
.batch-summary .stat .label{font-size:12px;color:#666;margin-top:4px}
.device-list{padding:24px 32px}
.device-item{border:1px solid #e0e0e0;border-radius:6px;padding:12px 16px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between}
.device-item .info{flex:1}
.device-item .name{font-weight:bold;font-size:14px}
.device-item .score{font-size:18px;font-weight:bold;width:80px;text-align:center}
.device-item .score.fail{color:#c62828}
.device-item .score.warn{color:#f57f17}
.device-item .score.pass{color:#2e7d32}
.device-item .issues{font-size:12px;color:#888;margin-top:4px}
.footer{padding:16px 32px;background:#fafafa;text-align:center;font-size:12px;color:#999}
</style>
</head>
<body>
<div class="batch-report">
  <div class="batch-header">
    <h1>GBDoctor 批量体检报告 %s</h1>
    <div style="font-size:13px;opacity:.85">体检时间: %s | 设备数: %d</div>
  </div>
  <div class="batch-summary">
    <div class="stats">
      <div class="stat"><div class="num">%d</div><div class="label">设备总数</div></div>
      <div class="stat"><div class="num" style="color:#2e7d32">%d</div><div class="label">通过</div></div>
      <div class="stat"><div class="num" style="color:#c62828">%d</div><div class="label">不通过</div></div>
      <div class="stat"><div class="num">%d%%</div><div class="label">通过率</div></div>
    </div>
  </div>
  <div class="device-list">
    <h2 style="font-size:16px;margin-bottom:16px">设备明细</h2>
`, batch.BatchID, batch.StartTime.Format("2006-01-02 15:04:05"), batch.DeviceCount,
		batch.DeviceCount, batch.PassedCount, batch.FailedCount, passRate)

	for _, report := range batch.Reports {
		scoreClass := "fail"
		if report.Score >= 80 {
			scoreClass = "pass"
		} else if report.Score >= 60 {
			scoreClass = "warn"
		}
		issueCount := len(report.AllIssues)
		html += fmt.Sprintf(`    <div class="device-item">
      <div class="info">
        <div class="name">%s</div>
        <div class="issues">问题: %d 个 | 证据: %d 条</div>
      </div>
      <div class="score %s">%d</div>
    </div>
`, report.DeviceID, issueCount, report.EvidenceCount, scoreClass, report.Score)
	}

	html += `  </div>
  <div class="footer">
    本报告由 GBDoctor 生成（专业版）<br>
    批量体检 → 高效验收
  </div>
</div>
</body>
</html>`

	return html, nil
}

// GenerateBatchReportFile 生成批量体检报告并写入文件。
func GenerateBatchReportFile(batch *BatchReportData, path string) error {
	html, err := GenerateBatchReport(batch)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(html), 0644)
}

func scoreClass(score int) string {
	if score >= 80 {
		return "pass"
	}
	if score >= 60 {
		return "warn"
	}
	return "fail"
}

func severityClass(s sip.Severity) string {
	switch s {
	case sip.SeverityBlocking:
		return "blocking"
	case sip.SeverityWarning:
		return "warning"
	case sip.SeverityAdvice:
		return "advice"
	}
	return ""
}

func templateHTML(s string) template.HTML {
	return template.HTML(strings.ReplaceAll(s, "\n", "<br>"))
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
