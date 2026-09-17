// Package batch 实现批量体检功能（V1.2）。
//
// N 台设备批量体检，生成项目验收报告。
// 社区版限制 10 台，专业版无限制。
package batch

import (
	"fmt"
	"sync"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/report"
	"gbdoctor/internal/sip"
)

// BatchConfig 为批量体检配置。
type BatchConfig struct {
	Devices     []DeviceConfig // 设备列表
	MaxParallel int            // 最大并发数
	FreeLimit   int            // 社区版限制（默认 10）
}

// DeviceConfig 为单个设备的体检配置。
type DeviceConfig struct {
	DeviceID   string
	ServerAddr string
	Password   string
	Transport  string
}

// BatchResult 为批量体检结果。
type BatchResult struct {
	BatchID     string
	StartTime   time.Time
	EndTime     time.Time
	TotalCount  int
	PassedCount int
	FailedCount int
	Reports     []*diag.ReportData
}

// BatchEngine 为批量体检引擎。
type BatchEngine struct {
	role       *sip.DeviceSideRole
	ruleEngine *sip.RuleEngine
	cfg        BatchConfig
}

// NewBatchEngine 创建批量体检引擎。
func NewBatchEngine(role *sip.DeviceSideRole, ruleEngine *sip.RuleEngine, cfg BatchConfig) *BatchEngine {
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 5
	}
	if cfg.FreeLimit <= 0 {
		cfg.FreeLimit = 10 // 社区版限制
	}
	return &BatchEngine{
		role:       role,
		ruleEngine: ruleEngine,
		cfg:        cfg,
	}
}

// RunBatch 执行批量体检。
// 返回批量结果和是否触发了限制。
func (e *BatchEngine) RunBatch() (*BatchResult, bool, error) {
	deviceCount := len(e.cfg.Devices)
	truncated := false

	// 社区版限制检查
	if deviceCount > e.cfg.FreeLimit {
		deviceCount = e.cfg.FreeLimit
		truncated = true
	}

	result := &BatchResult{
		BatchID:    fmt.Sprintf("BATCH-%s", time.Now().Format("20060102-150405")),
		StartTime:  time.Now(),
		TotalCount: deviceCount,
	}

	// 并发执行
	sem := make(chan struct{}, e.cfg.MaxParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < deviceCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			devCfg := e.cfg.Devices[idx]
			engine := diag.NewEngine(e.role, e.ruleEngine, diag.CheckConfig{
				DeviceID:   devCfg.DeviceID,
				Password:   devCfg.Password,
				Transport:  devCfg.Transport,
				ServerAddr: devCfg.ServerAddr,
			})
			r := engine.Run()

			mu.Lock()
			result.Reports = append(result.Reports, r)
			if r.Passed {
				result.PassedCount++
			} else {
				result.FailedCount++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	result.EndTime = time.Now()

	return result, truncated, nil
}

// GenerateBatchReport 生成批量体检报告 HTML。
func GenerateBatchReport(result *BatchResult) (string, error) {
	batchData := &report.BatchReportData{
		BatchID:     result.BatchID,
		StartTime:   result.StartTime,
		DeviceCount: result.TotalCount,
		PassedCount: result.PassedCount,
		FailedCount: result.FailedCount,
		Reports:     result.Reports,
	}
	return report.GenerateBatchReport(batchData)
}

// GenerateBatchReportFile 生成批量体检报告并写入文件。
func GenerateBatchReportFile(result *BatchResult, path string) error {
	batchData := &report.BatchReportData{
		BatchID:     result.BatchID,
		StartTime:   result.StartTime,
		DeviceCount: result.TotalCount,
		PassedCount: result.PassedCount,
		FailedCount: result.FailedCount,
		Reports:     result.Reports,
	}
	return report.GenerateBatchReportFile(batchData, path)
}
