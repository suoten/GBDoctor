package sip

import (
	"testing"
)

func TestRuleEngineAddAndCount(t *testing.T) {
	engine := NewRuleEngine()
	if engine.RuleCount() != 0 {
		t.Errorf("初始规则数 = %d, want 0", engine.RuleCount())
	}

	engine.AddRule(Rule{
		ID:       "TEST-001",
		Category: "register",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "auth_fail"},
		Title:    "测试规则",
	})
	if engine.RuleCount() != 1 {
		t.Errorf("添加后规则数 = %d, want 1", engine.RuleCount())
	}

	rules := engine.Rules()
	if len(rules) != 1 || rules[0].ID != "TEST-001" {
		t.Errorf("Rules() 返回不正确: %v", rules)
	}
}

func TestEvaluateRegisterAuthFail(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "REG-TEST-001",
		Category: "register",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "auth_fail"},
		Title:    "注册鉴权失败",
		Explain:  "测试",
	})

	// 鉴权失败应匹配
	fact := RegisterFact{
		Kind:     "auth_fail",
		DeviceID: "34020000001320000001",
		Source:   "192.168.1.100:5060",
	}
	issues := engine.EvaluateRegister(fact)
	if len(issues) != 1 {
		t.Errorf("auth_fail 应匹配 1 条规则, got %d", len(issues))
	}
	if issues[0].RuleID != "REG-TEST-001" {
		t.Errorf("RuleID = %s, want REG-TEST-001", issues[0].RuleID)
	}

	// 注册成功不匹配
	fact2 := RegisterFact{
		Kind:     "registered",
		DeviceID: "34020000001320000001",
	}
	issues2 := engine.EvaluateRegister(fact2)
	if len(issues2) != 0 {
		t.Errorf("registered 不应匹配 auth_fail 规则")
	}
}

func TestEvaluateRegisterNAT(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "REG-NAT-TEST",
		Category: "register",
		Severity: "warning",
		Trigger:  TriggerDef{Condition: "nat"},
		Title:    "NAT 地址不匹配",
	})

	fact := RegisterFact{
		Kind:        "registered",
		DeviceID:    "34020000001320000001",
		NATMismatch: true,
	}
	issues := engine.EvaluateRegister(fact)
	if len(issues) != 1 {
		t.Errorf("NAT 不匹配应触发规则, got %d", len(issues))
	}
}

func TestEvaluateRegisterDeviceIDInvalid(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "REG-DEVICEID-TEST",
		Category: "register",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "deviceid"},
		Title:    "设备编码不合规",
	})

	fact := RegisterFact{
		Kind:          "registered",
		DeviceID:      "abc",
		DeviceIDValid: false,
	}
	issues := engine.EvaluateRegister(fact)
	if len(issues) != 1 {
		t.Errorf("DeviceID 无效应触发规则, got %d", len(issues))
	}
}

func TestEvaluateKeepaliveMissingSN(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "KA-SN-TEST",
		Category: "keepalive",
		Severity: "warning",
		Trigger:  TriggerDef{Condition: "missing_sn"},
		Title:    "心跳缺少 SN",
	})

	fact := KeepaliveFact{
		DeviceID: "34020000001320000001",
		XML:      `<Notify><CmdType>Keepalive</CmdType><DeviceID>34020000001320000001</DeviceID><Status>OK</Status></Notify>`,
		OK:       true,
	}
	issues := engine.EvaluateKeepalive(fact)
	if len(issues) != 1 {
		t.Errorf("缺少 SN 应触发规则, got %d", len(issues))
	}
}

func TestEvaluateKeepaliveStatusNotOK(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "KA-STATUS-TEST",
		Category: "keepalive",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "missing_status"},
		Title:    "心跳状态异常",
	})

	fact := KeepaliveFact{
		DeviceID: "34020000001320000001",
		XML:      `<Notify><CmdType>Keepalive</CmdType><SN>1</SN><DeviceID>34020000001320000001</DeviceID><Status>ERROR</Status></Notify>`,
		OK:       true,
	}
	issues := engine.EvaluateKeepalive(fact)
	if len(issues) != 1 {
		t.Errorf("Status!=OK 应触发规则, got %d", len(issues))
	}
}

func TestEvaluateCatalogEmpty(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "CAT-EMPTY-TEST",
		Category: "catalog",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "empty"},
		Title:    "目录为空",
	})

	fact := CatalogFact{
		DeviceID: "34020000001320000001",
		Items:    []CatalogItem{},
	}
	issues := engine.EvaluateCatalog(fact)
	if len(issues) != 1 {
		t.Errorf("空目录应触发规则, got %d", len(issues))
	}
}

func TestEvaluateCatalogErrCode(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "CAT-ERR-TEST",
		Category: "catalog",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "errcode"},
		Title:    "目录查询错误",
	})

	fact := CatalogFact{
		DeviceID: "34020000001320000001",
		ErrCode:  "100",
	}
	issues := engine.EvaluateCatalog(fact)
	if len(issues) != 1 {
		t.Errorf("ErrCode 非零应触发规则, got %d", len(issues))
	}
}

func TestEvaluateSDP(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "INV-SSRC-TEST",
		Category: "invite",
		Severity: "warning",
		Trigger:  TriggerDef{Condition: "sdp_no_ssrc"},
		Title:    "SDP 缺少 SSRC",
	})

	devs := []Deviation{
		{Kind: "sdp_no_ssrc", Detail: "SDP 缺少 y= 字段"},
	}
	sdp := &SDPInfo{SessionName: "Play", IPAddress: "203.0.113.1", Port: 6000}
	issues := engine.EvaluateSDP(devs, sdp)
	if len(issues) != 1 {
		t.Errorf("sdp_no_ssrc 应触发规则, got %d", len(issues))
	}
}

func TestEvaluateRTPHighLoss(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "RTP-LOSS-TEST",
		Category: "rtp",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "loss"},
		Title:    "丢包率过高",
	})

	stats := NewRTPStats()
	for i := 0; i < 50; i++ {
		stats.Add(&RTPPacket{SeqNumber: uint16(i * 3), Size: 1000})
	}
	a := AnalyzeRTPStream(stats)
	issues := engine.EvaluateRTP(a)
	if len(issues) == 0 {
		t.Error("高丢包率应触发 RTP 规则")
	}
}

func TestEvaluateClockOffset(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "CLK-OFFSET-TEST",
		Category: "clock",
		Severity: "warning",
		Trigger:  TriggerDef{Condition: "offset"},
		Title:    "时间偏差过大",
	})

	// 偏差 2 分钟
	fact := ClockFact{
		DeviceID: "34020000001320000001",
		Offset:   120 * 1e9, // 120 秒
	}
	issues := engine.EvaluateClock(fact)
	if len(issues) != 1 {
		t.Errorf("大偏差应触发时钟规则, got %d", len(issues))
	}
}

func TestEvaluateNetwork(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{
		ID:       "NET-PORT-TEST",
		Category: "network",
		Severity: "blocking",
		Trigger:  TriggerDef{Condition: "port_blocked"},
		Title:    "端口不可达",
	})

	devs := []Deviation{
		{Kind: "port_blocked", Detail: "SIP 5060 不可达"},
	}
	issues := engine.EvaluateNetwork(devs)
	if len(issues) != 1 {
		t.Errorf("port_blocked 应触发规则, got %d", len(issues))
	}
}
