package sip

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Severity 为问题严重程度。
type Severity string

const (
	SeverityBlocking Severity = "blocking" // 阻断级（不通）
	SeverityWarning  Severity = "warning"  // 警告级（能用但埋雷）
	SeverityAdvice   Severity = "advice"   // 建议级（最佳实践）
)

// Stage 为体检环节。
type Stage string

const (
	StageRegister   Stage = "register"
	StageKeepalive  Stage = "keepalive"
	StageCatalog    Stage = "catalog"
	StageInvite     Stage = "invite"
	StageRTP        Stage = "rtp"
	StageClock      Stage = "clock"
	StageDeviceInfo Stage = "deviceinfo"
	StagePTZ        Stage = "ptz"
	StageAlarm      Stage = "alarm"
	StageVoice      Stage = "voice"
	StageRecord     Stage = "record"
	StageCascade    Stage = "cascade"
	StageGB2022     Stage = "gb2022"
	StageNetwork    Stage = "network"
)

// Issue 为规则命中后产出的诊断问题。
type Issue struct {
	RuleID      string
	Category    Stage
	Severity    Severity
	Title       string
	Evidence    []string
	Explain     string
	Advice      []string
	VendorNotes map[string]string
}

// Rule 为声明式诊断规则。
type Rule struct {
	ID          string            `yaml:"rule_id"`
	Category    string            `yaml:"category"`
	Severity    string            `yaml:"severity"`
	Trigger     TriggerDef        `yaml:"trigger"`
	Title       string            `yaml:"title"`
	Evidence    []string          `yaml:"evidence"`
	Explain     string            `yaml:"explain"`
	Advice      []string          `yaml:"advice"`
	VendorNotes map[string]string `yaml:"vendor_notes"`
}

// TriggerDef 为触发条件定义。
type TriggerDef struct {
	Condition string `yaml:"condition"`
}

// RuleEngine 为规则引擎。
type RuleEngine struct {
	rules []Rule
	mu    sync.Mutex
}

// NewRuleEngine 创建规则引擎。
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{}
}

// AddRule 添加一条规则。
func (e *RuleEngine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// Rules 返回规则列表。
func (e *RuleEngine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// RuleCount 返回规则数量。
func (e *RuleEngine) RuleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rules)
}

// EvaluateRegister 对注册事实执行规则匹配。
func (e *RuleEngine) EvaluateRegister(f RegisterFact) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "register" {
			continue
		}
		if matchRegister(r, f) {
			issues = append(issues, ruleToIssue(r, []string{fmt.Sprintf("设备: %s, 来源: %s", f.DeviceID, f.Source)}))
		}
	}
	return issues
}

// EvaluateKeepalive 对心跳事实执行规则匹配。
func (e *RuleEngine) EvaluateKeepalive(f KeepaliveFact) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "keepalive" {
			continue
		}
		if matchKeepalive(r, f) {
			issues = append(issues, ruleToIssue(r, []string{fmt.Sprintf("设备: %s, SN: %s", f.DeviceID, XMLTagValue(f.XML, "SN"))}))
		}
	}
	return issues
}

// EvaluateCatalog 对目录应答执行规则匹配。
func (e *RuleEngine) EvaluateCatalog(f CatalogFact) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "catalog" {
			continue
		}
		if matchCatalog(r, f) {
			issues = append(issues, ruleToIssue(r, []string{fmt.Sprintf("设备: %s, 通道数: %d", f.DeviceID, len(f.Items))}))
		}
	}
	return issues
}

// EvaluateSDP 对 SDP 校验结果执行规则匹配。
func (e *RuleEngine) EvaluateSDP(devs []Deviation, sdp *SDPInfo) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "invite" {
			continue
		}
		for _, d := range devs {
			if strings.Contains(strings.ToLower(r.Trigger.Condition), strings.ToLower(d.Kind)) {
				issues = append(issues, ruleToIssue(r, []string{d.Detail}))
			}
		}
	}
	return issues
}

// EvaluateRTP 对 RTP 分析结果执行规则匹配。
func (e *RuleEngine) EvaluateRTP(analysis RTPStreamAnalysis) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "rtp" {
			continue
		}
		cond := strings.ToLower(r.Trigger.Condition)
		if analysis.IsScreenCorrupt && strings.Contains(cond, "loss") {
			issues = append(issues, ruleToIssue(r, analysis.Conclusions))
		}
		if analysis.IsStuttering && strings.Contains(cond, "stutter") {
			issues = append(issues, ruleToIssue(r, analysis.Conclusions))
		}
	}
	return issues
}

// EvaluateClock 对时钟偏差执行规则匹配。
func (e *RuleEngine) EvaluateClock(f ClockFact) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "clock" {
			continue
		}
		cond := strings.ToLower(r.Trigger.Condition)
		abs := f.Offset
		if abs < 0 {
			abs = -abs
		}
		if strings.Contains(cond, "offset") && abs > 60*time.Second {
			issues = append(issues, ruleToIssue(r, ClockOffsetConclusions(f.Offset)))
		}
	}
	return issues
}

// EvaluateNetwork 对网络诊断结果执行规则匹配。
func (e *RuleEngine) EvaluateNetwork(devs []Deviation) []Issue {
	var issues []Issue
	e.mu.Lock()
	rules := e.rules
	e.mu.Unlock()

	for _, r := range rules {
		if r.Category != "network" {
			continue
		}
		for _, d := range devs {
			if strings.Contains(strings.ToLower(r.Trigger.Condition), strings.ToLower(d.Kind)) {
				issues = append(issues, ruleToIssue(r, []string{d.Detail}))
			}
		}
	}
	return issues
}

func matchRegister(r Rule, f RegisterFact) bool {
	cond := strings.ToLower(r.Trigger.Condition)
	switch {
	case strings.Contains(cond, "auth_fail") && f.Kind == "auth_fail":
		return true
	case strings.Contains(cond, "nat") && f.NATMismatch:
		return true
	case strings.Contains(cond, "deviceid") && !f.DeviceIDValid:
		return true
	case strings.Contains(cond, "timeout") && f.Kind == "challenge" && f.MaxInSize == 0:
		return true
	case strings.Contains(cond, "algorithm") && f.DeclaredAlg != "" && f.DeclaredAlg != AlgoMD5:
		return true
	}
	return false
}

func matchKeepalive(r Rule, f KeepaliveFact) bool {
	cond := strings.ToLower(r.Trigger.Condition)
	if strings.Contains(cond, "missing_status") {
		status := XMLTagValue(f.XML, "Status")
		if status != "OK" && status != "" {
			return true
		}
	}
	if strings.Contains(cond, "missing_sn") {
		sn := XMLTagValue(f.XML, "SN")
		if sn == "" {
			return true
		}
	}
	return false
}

func matchCatalog(r Rule, f CatalogFact) bool {
	cond := strings.ToLower(r.Trigger.Condition)
	if strings.Contains(cond, "empty") && len(f.Items) == 0 {
		return true
	}
	if strings.Contains(cond, "errcode") && f.ErrCode != "" && f.ErrCode != "0" {
		return true
	}
	if strings.Contains(cond, "deviceid") {
		for _, item := range f.Items {
			devs := CatalogItemValidations(item)
			if len(devs) > 0 {
				return true
			}
		}
	}
	return false
}

func ruleToIssue(r Rule, evidence []string) Issue {
	return Issue{
		RuleID:      r.ID,
		Category:    Stage(r.Category),
		Severity:    Severity(r.Severity),
		Title:       r.Title,
		Evidence:    evidence,
		Explain:     r.Explain,
		Advice:      r.Advice,
		VendorNotes: r.VendorNotes,
	}
}
