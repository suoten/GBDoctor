package batch

import (
	"testing"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/sip"
)

func TestNewBatchEngine(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001",
		Password: "12345678",
	})
	engine := NewBatchEngine(role, nil, BatchConfig{
		Devices: []DeviceConfig{
			{DeviceID: "34020000001320000001"},
		},
	})
	if engine == nil {
		t.Fatal("引擎不应为 nil")
	}
	if engine.cfg.MaxParallel != 5 {
		t.Errorf("MaxParallel = %d, want 5 (默认)", engine.cfg.MaxParallel)
	}
	if engine.cfg.FreeLimit != 10 {
		t.Errorf("FreeLimit = %d, want 10 (默认)", engine.cfg.FreeLimit)
	}
}

func TestBatchEngineFreeLimit(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001",
		Password: "12345678",
	})
	engine := NewBatchEngine(role, nil, BatchConfig{
		Devices:   make([]DeviceConfig, 15), // 超过免费限制
		FreeLimit: 5,
	})
	if engine.cfg.FreeLimit != 5 {
		t.Errorf("FreeLimit = %d, want 5", engine.cfg.FreeLimit)
	}
}

func TestBatchResultStructure(t *testing.T) {
	// 验证 BatchResult 结构体字段
	r := &BatchResult{
		BatchID:     "BATCH-TEST",
		TotalCount:  5,
		PassedCount: 3,
		FailedCount: 2,
	}
	if r.BatchID != "BATCH-TEST" {
		t.Error("BatchID 不正确")
	}
	if r.TotalCount != 5 {
		t.Error("TotalCount 不正确")
	}
	if r.PassedCount != 3 {
		t.Error("PassedCount 不正确")
	}
	if r.FailedCount != 2 {
		t.Error("FailedCount 不正确")
	}
}

func TestDeviceConfigFields(t *testing.T) {
	cfg := DeviceConfig{
		DeviceID:   "34020000001320000001",
		ServerAddr: "192.168.1.100:5060",
		Password:   "12345678",
		Transport:  "udp",
	}
	if cfg.DeviceID != "34020000001320000001" {
		t.Error("DeviceID 不正确")
	}
	if cfg.ServerAddr != "192.168.1.100:5060" {
		t.Error("ServerAddr 不正确")
	}
	if cfg.Password != "12345678" {
		t.Error("Password 不正确")
	}
	if cfg.Transport != "udp" {
		t.Error("Transport 不正确")
	}
}

func TestBatchConfigWithDiagEngine(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001",
		Password: "12345678",
	})
	re := sip.NewRuleEngine()
	engine := NewBatchEngine(role, re, BatchConfig{
		Devices: []DeviceConfig{
			{DeviceID: "34020000001320000001", Transport: "udp"},
		},
		MaxParallel: 3,
	})
	if engine.ruleEngine == nil {
		t.Error("ruleEngine 不应为 nil")
	}
}

// 验证 diag.Engine 与 batch 的协作
func TestDiagEngineCompatible(t *testing.T) {
	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001",
		Password: "12345678",
	})
	re := sip.NewRuleEngine()
	engine := diag.NewEngine(role, re, diag.CheckConfig{
		DeviceID: "34020000001320000001",
	})
	if engine == nil {
		t.Fatal("diag.Engine 不应为 nil")
	}
	if engine.RuleEngine() == nil {
		t.Error("RuleEngine() 不应为 nil")
	}
}
