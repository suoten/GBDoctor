// Package rules 实现 GBDoctor 规则库的加载与管理。
//
// 规则文件为 YAML 格式，与代码解耦（spec §7.3 规则库体系）。
// 内置规则编译进二进制（embed），社区版可在线更新。
package rules

import (
	_ "embed"
	"fmt"
	"os"

	"gbdoctor/internal/sip"
	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var builtinRulesYAML []byte

// LoadRules 从 YAML 字节加载规则列表。
func LoadRules(data []byte) ([]sip.Rule, error) {
	// yaml.v3 顶层是列表，直接 unmarshal 为 slice
	var items []sip.Rule
	if err := yaml.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("规则文件解析失败: %w", err)
	}
	return items, nil
}

// LoadBuiltinRules 加载内置规则。
func LoadBuiltinRules() ([]sip.Rule, error) {
	return LoadRules(builtinRulesYAML)
}

// LoadRulesFromFile 从文件加载规则。
func LoadRulesFromFile(path string) ([]sip.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}
	return LoadRules(data)
}

// NewEngineWithBuiltinRules 创建包含内置规则的规则引擎。
func NewEngineWithBuiltinRules() (*sip.RuleEngine, error) {
	rules, err := LoadBuiltinRules()
	if err != nil {
		return nil, err
	}
	engine := sip.NewRuleEngine()
	for _, r := range rules {
		engine.AddRule(r)
	}
	return engine, nil
}
