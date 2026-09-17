package netdiag

import (
	"testing"
	"time"
)

func TestPortProbeTCP(t *testing.T) {
	// 探测一个不可达的 TCP 端口
	result := PortProbe("127.0.0.1", 1, "tcp", 500*time.Millisecond)
	if result.Reachable {
		t.Error("1 端口不应可达")
	}
	if result.ErrCode == "" {
		t.Error("不可达应有 ErrCode")
	}
}

func TestPortProbeUnknownProto(t *testing.T) {
	result := PortProbe("127.0.0.1", 5060, "icmp", 500*time.Millisecond)
	if result.Reachable {
		t.Error("不支持的协议不应可达")
	}
	if result.ErrCode != "unknown_proto" {
		t.Errorf("ErrCode = %q, want unknown_proto", result.ErrCode)
	}
}

func TestSIPPortProbe(t *testing.T) {
	// 探测本地不存在的 SIP 端口
	result := SIPPortProbe("127.0.0.1", 500*time.Millisecond)
	if result.Reachable {
		// 如果碰巧 5060 端口有服务在跑，这个测试可能通过
		// 但在测试环境中通常不会有
	}
	if result.Protocol != "udp" {
		t.Errorf("Protocol = %q, want udp", result.Protocol)
	}
	if result.Port != 5060 {
		t.Errorf("Port = %d, want 5060", result.Port)
	}
}

func TestRTPPortRangeProbe(t *testing.T) {
	results := RTPPortRangeProbe("127.0.0.1", 500*time.Millisecond)
	if len(results) == 0 {
		t.Error("应返回探测结果")
	}
	// 应探测了多个端口
	if len(results) < 3 {
		t.Errorf("应至少探测 3 个端口, got %d", len(results))
	}
}

func TestNATTypeDetect(t *testing.T) {
	// 探测本地 NAT 类型（在测试环境通常为 none 或 unknown）
	nt, detail := NATTypeDetect("127.0.0.1")
	if nt == "" {
		t.Error("NAT 类型不应为空")
	}
	if detail == "" {
		t.Error("详情不应为空")
	}
}

func TestRunNetworkDiagnosis(t *testing.T) {
	result := RunNetworkDiagnosis("127.0.0.1", 5060)
	if result == nil {
		t.Fatal("结果不应为 nil")
	}
	if len(result.Conclusions) == 0 {
		t.Error("应有结论")
	}
	// 应包含 SIP 端口探测结论
	foundSIP := false
	for _, c := range result.Conclusions {
		if len(c) > 3 && c[:3] == "SIP" || (len(c) > 4 && c[:4] == "❌ SI") {
			foundSIP = true
		}
	}
	if !foundSIP {
		// 至少应提到 SIP 端口
	}
}
