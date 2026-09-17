// Package netdiag 实现独立网络诊断模块（V1.1）。
//
// 检测项：端口可达性、NAT 类型探测、防火墙检测、RTP 端口范围探测。
// 这是 GB28181 接入诊断的前置步骤——网络不通，协议层再标准也没用。
package netdiag

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gbdoctor/internal/sip"
)

// NetCheckResult 为网络诊断结果。
type NetCheckResult struct {
	Target    string
	Port      int
	Protocol  string // udp/tcp
	Reachable bool
	Latency   time.Duration
	ErrCode   string
	ErrDetail string
	TS        time.Time
}

// NATType 为 NAT 类型枚举。
type NATType string

const (
	NATNone           NATType = "none"            // 无 NAT
	NATFullCone       NATType = "full_cone"       // 全锥形
	NATRestricted     NATType = "restricted"      // 限制锥形
	NATPortRestricted NATType = "port_restricted" // 端口限制锥形
	NATSymmetric      NATType = "symmetric"       // 对称型（最难穿透）
	NATUnknown        NATType = "unknown"
)

// PortProbe 探测目标端口是否可达。
func PortProbe(host string, port int, proto string, timeout time.Duration) NetCheckResult {
	result := NetCheckResult{
		Target: host, Port: port, Protocol: proto,
		TS: time.Now(),
	}
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	switch strings.ToLower(proto) {
	case "tcp":
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		result.Latency = time.Since(start)
		if err != nil {
			result.Reachable = false
			result.ErrCode = "connect_failed"
			result.ErrDetail = err.Error()
		} else {
			result.Reachable = true
			_ = conn.Close()
		}

	case "udp":
		// UDP 探测：发送一个空 SIP REGISTER 包，看是否有响应
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			result.Reachable = false
			result.ErrCode = "resolve_failed"
			result.ErrDetail = err.Error()
			return result
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			result.Reachable = false
			result.ErrCode = "dial_failed"
			result.ErrDetail = err.Error()
			return result
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(timeout))
		probe := []byte("REGISTER sip:probe SIP/2.0\r\nVia: SIP/2.0/UDP probe\r\nFrom: <sip:probe@probe>\r\nTo: <sip:probe@probe>\r\nCall-ID: probe\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n")
		start := time.Now()
		_, err = conn.Write(probe)
		if err != nil {
			result.Reachable = false
			result.ErrCode = "send_failed"
			result.ErrDetail = err.Error()
			return result
		}

		buf := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(buf)
		result.Latency = time.Since(start)
		if err != nil {
			// UDP 探测的天然局限：无响应可能是端口未监听、防火墙丢弃、
			// 也可能是服务不回应探测报文——无法区分，结论置信度低
			result.Reachable = false
			result.ErrCode = "no_response"
			result.ErrDetail = "UDP 无响应（端口未监听/防火墙丢弃/服务不回应探测报文，UDP 探测无法区分，置信度低）"
		} else if n > 0 {
			// 收到响应说明端口可达
			result.Reachable = true
		}

	default:
		result.Reachable = false
		result.ErrCode = "unknown_proto"
		result.ErrDetail = "不支持的协议: " + proto
	}

	return result
}

// SIPPortProbe 专门探测 SIP 5060 端口。
func SIPPortProbe(host string, timeout time.Duration) NetCheckResult {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return PortProbe(host, 5060, "udp", timeout)
}

// RTPPortRangeProbe 探测 RTP 端口范围是否被防火墙拦截。
// 检测策略：向目标网段的几个常见 RTP 端口发送 UDP 包，
// 如果全部无响应，可能是防火墙拦截（但也可能是端口确实未开放）。
func RTPPortRangeProbe(host string, timeout time.Duration) []NetCheckResult {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	// 探测常见 RTP 端口范围中的几个端口
	ports := []int{10000, 20000, 30000, 40000, 50000, 60000}
	var results []NetCheckResult
	for _, port := range ports {
		results = append(results, PortProbe(host, port, "udp", timeout))
	}
	return results
}

// NATTypeDetect 探测 NAT/出口形态（诚实版）。
// 真实的 NAT 锥形类型判定需要 STUN 服务器（RFC 5389/8489），
// 本机本地地址的比较无法替代 STUN。这里仅检测：
// ① 到不同目标的出口本地地址是否一致（多出口/多网卡路由信号）；
// ② 出口地址是否为公网 IP（仅此可断定无 NAT）。
// 其余情况一律返回 NATUnknown，绝不给出未经证实的“对称型”结论。
func NATTypeDetect(target string) (NATType, string) {
	conn1, err := net.DialTimeout("udp", net.JoinHostPort(target, "9"), 2*time.Second)
	if err != nil {
		return NATUnknown, "无法探测出口地址: " + err.Error()
	}
	localAddr1 := conn1.LocalAddr().String()
	_ = conn1.Close()

	conn2, err := net.DialTimeout("udp", "8.8.8.8:9", 2*time.Second)
	if err != nil {
		return NATUnknown, "无法探测备用出口地址: " + err.Error()
	}
	localAddr2 := conn2.LocalAddr().String()
	_ = conn2.Close()

	host, _, _ := net.SplitHostPort(localAddr1)
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
		return NATNone, fmt.Sprintf("出口地址 %s 为公网 IP，无 NAT", host)
	}

	if localAddr1 != localAddr2 {
		return NATUnknown, fmt.Sprintf(
			"到不同目标的本地出口地址不同（%s vs %s），存在多网卡/多出口路由。NAT 锥形类型需 STUN 检测，本工具未纳入；请以真实注册/取流结果为准",
			localAddr1, localAddr2)
	}
	return NATUnknown, fmt.Sprintf(
		"单出口（本机地址 %s）。NAT 锥形类型需 STUN 检测，本工具未纳入；若跨网段接入异常，请优先检查路由/防火墙而非 NAT 类型", host)
}

// NetworkDiagnosis 为完整网络诊断结果。
type NetworkDiagnosis struct {
	TS          time.Time
	SIPPort     NetCheckResult
	RTPPorts    []NetCheckResult
	NATType     NATType
	NATDetail   string
	Conclusions []string
	Deviations  []sip.Deviation
}

// RunNetworkDiagnosis 执行完整网络诊断。
func RunNetworkDiagnosis(target string, sipPort int) *NetworkDiagnosis {
	diag := &NetworkDiagnosis{TS: time.Now()}
	_ = sipPort

	// SIP 端口探测
	diag.SIPPort = SIPPortProbe(target, 3*time.Second)
	if diag.SIPPort.Reachable {
		diag.Conclusions = append(diag.Conclusions, fmt.Sprintf("✅ SIP 5060/UDP 可达（延迟 %s）", diag.SIPPort.Latency))
	} else {
		diag.Conclusions = append(diag.Conclusions, fmt.Sprintf("❌ SIP 5060/UDP 不可达: %s", diag.SIPPort.ErrDetail))
		diag.Deviations = append(diag.Deviations, sip.Deviation{
			Kind:   "port_blocked",
			Detail: fmt.Sprintf("SIP 5060/UDP 不可达: %s", diag.SIPPort.ErrDetail),
		})
	}

	// RTP 端口范围探测（诚实版）：RTP 端口仅在推流时才有服务监听，
	// 无响应属正常现象，不能据此断定防火墙拦截；真实 RTP 连通性
	// 以体检的媒体流环节为准。
	diag.RTPPorts = RTPPortRangeProbe(target, 2*time.Second)
	responded := 0
	for _, r := range diag.RTPPorts {
		if r.Reachable {
			responded++
		}
	}
	if responded > 0 {
		diag.Conclusions = append(diag.Conclusions,
			fmt.Sprintf("ℹ️ RTP 探测端口 %d/%d 有响应（可能是其他服务），不能作为 RTP 连通性依据", responded, len(diag.RTPPorts)))
	} else {
		diag.Conclusions = append(diag.Conclusions,
			"ℹ️ RTP 探测端口全部无响应——属正常现象（RTP 端口仅在推流时才监听），不代表防火墙拦截；真实 RTP 连通性请以体检的媒体流环节结果为准")
	}

	// NAT 类型探测（诚实版，不产出未经证实的对称型结论）
	nt, detail := NATTypeDetect(target)
	diag.NATType = nt
	diag.NATDetail = detail
	diag.Conclusions = append(diag.Conclusions, fmt.Sprintf("NAT/出口形态: %s (%s)", nt, detail))
	if nt == NATSymmetric {
		diag.Deviations = append(diag.Deviations, sip.Deviation{
			Kind:   "nat_type",
			Detail: "对称型 NAT 可能导致注册失败",
		})
	}

	return diag
}
