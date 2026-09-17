// Package pcap implements offline pcap file analysis for GB28181 diagnostics.
//
// 解析 pcap 抓包文件中的 SIP/RTP 报文，复用诊断引擎的分析逻辑，
// 输出结构化诊断结论。不需要网卡抓包能力，仅做离线文件分析。
package sip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// PcapPacket 为从 pcap 文件解析出的单个报文。
type PcapPacket struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string // UDP / TCP
	Raw       []byte
}

// PcapAnalysisResult 为 pcap 离线分析结果。
type PcapAnalysisResult struct {
	FileName    string
	PacketCount int
	SIPCount    int
	RTPCount    int
	SIPPackets  []PcapPacket
	RTPPackets  []PcapPacket
	Stats       *RTPStats
	Analysis    RTPStreamAnalysis
	RegisterOK  bool
	InviteOK    bool
	Issues      []Issue
	Facts       []string
	TS          time.Time
}

// AnalyzePcap 分析 pcap 报文列表（已解析为 PcapPacket）。
// 自动识别 SIP 报文和 RTP 报文，执行诊断分析。
func AnalyzePcap(packets []PcapPacket, fileName string) *PcapAnalysisResult {
	result := &PcapAnalysisResult{
		FileName:    fileName,
		PacketCount: len(packets),
		TS:          time.Now(),
		Stats:       NewRTPStats(),
	}

	// 分类报文
	for _, pkt := range packets {
		// SIP 报文特征：UDP 端口 5060 或 TCP 端口 5060，或以 SIP/2.0 开头
		isSIP := pkt.SrcPort == 5060 || pkt.DstPort == 5060
		if !isSIP && len(pkt.Raw) >= 8 {
			prefix := string(pkt.Raw[:8])
			if strings.HasPrefix(prefix, "REGISTER") || strings.HasPrefix(prefix, "SIP/2.0") ||
				strings.HasPrefix(prefix, "INVITE") || strings.HasPrefix(prefix, "MESSAGE") ||
				strings.HasPrefix(prefix, "BYE") || strings.HasPrefix(prefix, "ACK") ||
				strings.HasPrefix(prefix, "OPTIONS") {
				isSIP = true
			}
		}

		// RTP 报文特征：前两字节 Version=2 (0x80)
		isRTP := false
		if len(pkt.Raw) >= 2 {
			if pkt.Raw[0]&0xC0 == 0x80 && pkt.Raw[1]&0x7F < 35 {
				isRTP = true
			}
		}

		if isSIP {
			result.SIPCount++
			result.SIPPackets = append(result.SIPPackets, pkt)
		} else if isRTP {
			result.RTPCount++
			result.RTPPackets = append(result.RTPPackets, pkt)
			// 解析 RTP 包并更新统计
			rtpPkt := ParseRTP(pkt.Raw)
			if rtpPkt != nil {
				result.Stats.Add(rtpPkt)
			}
		}
	}

	result.Facts = append(result.Facts, fmt.Sprintf("总报文数: %d (SIP: %d, RTP: %d)",
		result.PacketCount, result.SIPCount, result.RTPCount))

	// 分析 SIP 报文
	for _, pkt := range result.SIPPackets {
		msg := Parse(pkt.Raw)
		if msg.IsRequest {
			switch msg.Method {
			case "REGISTER":
				result.Facts = append(result.Facts, fmt.Sprintf("REGISTER: %s:%d → %s:%d",
					pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort))
			case "INVITE":
				result.InviteOK = true
				result.Facts = append(result.Facts, fmt.Sprintf("INVITE: %s:%d → %s:%d",
					pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort))
			}
		} else {
			if msg.StatusCode == 200 {
				if strings.Contains(msg.Headers.Get("cseq"), "REGISTER") {
					result.RegisterOK = true
					result.Facts = append(result.Facts, "REGISTER 200 OK ✅")
				}
			}
		}
	}

	// 分析 RTP 流
	if result.RTPCount > 0 {
		result.Analysis = AnalyzeRTPStream(result.Stats)
		result.Facts = append(result.Facts, RTPToText(result.Analysis))
		if result.Analysis.IsScreenCorrupt {
			result.Issues = append(result.Issues, Issue{
				RuleID:   "RTP-PCAP-LOSS",
				Category: StageRTP,
				Severity: SeverityBlocking,
				Title:    "pcap 分析：RTP 丢包率过高",
				Explain:  fmt.Sprintf("从抓包文件中分析到 RTP 丢包率 %.1f%%", result.Analysis.LossRate),
				Advice:   []string{"检查网络带宽", "降低编码码率"},
			})
		}
	} else {
		if result.InviteOK {
			result.Issues = append(result.Issues, Issue{
				RuleID:   "RTP-PCAP-NO-STREAM",
				Category: StageRTP,
				Severity: SeverityBlocking,
				Title:    "pcap 分析：INVITE 成功但无 RTP 流",
				Explain:  "抓包文件中有 INVITE 200 OK 但未捕获到 RTP 报文。可能是抓包范围太窄或设备未推流。",
				Advice:   []string{"扩大抓包端口范围", "确认设备在抓包期间正在推流"},
			})
		}
	}

	if !result.RegisterOK {
		result.Issues = append(result.Issues, Issue{
			RuleID:   "REG-PCAP-NO-OK",
			Category: StageRegister,
			Severity: SeverityWarning,
			Title:    "pcap 分析：未发现注册成功",
			Explain:  "抓包文件中未发现 REGISTER 200 OK 报文。",
			Advice:   []string{"确认抓包覆盖了注册流程", "检查是否有 401 质询但无后续 REGISTER"},
		})
	}

	return result
}

// ParsePcapFile 解析 pcap 文件（libpcap 格式）。
// 支持全局头 + 报文记录格式。返回报文列表。
func ParsePcapFile(data []byte) ([]PcapPacket, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("pcap 文件头过短")
	}

	// 全局头（24 字节）
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xa1b2c3d4 {
		return nil, fmt.Errorf("不是标准 pcap 格式 (magic=0x%08X)", magic)
	}

	// 版本
	// versionMajor := binary.LittleEndian.Uint16(data[4:6])
	// versionMinor := binary.LittleEndian.Uint16(data[6:8])
	// snapLen := binary.LittleEndian.Uint32(data[16:20])
	linkType := binary.LittleEndian.Uint32(data[20:24])

	offset := 24
	var packets []PcapPacket

	for offset+16 <= len(data) {
		// 报文记录头（16 字节）
		tsSec := binary.LittleEndian.Uint32(data[offset : offset+4])
		tsUsec := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		capLen := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		origLen := binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		_ = origLen

		offset += 16
		if offset+int(capLen) > len(data) {
			break
		}

		pktData := data[offset : offset+int(capLen)]
		offset += int(capLen)

		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)

		// 解析链路层
		pkt, err := parsePacket(pktData, linkType, ts)
		if err != nil {
			continue
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

// parsePacket 解析单个报文。
func parsePacket(data []byte, linkType uint32, ts time.Time) (PcapPacket, error) {
	var ipOffset int

	switch linkType {
	case 1: // Ethernet
		if len(data) < 14 {
			return PcapPacket{}, fmt.Errorf("以太网帧过短")
		}
		ipOffset = 14
	case 101: // Raw IP
		ipOffset = 0
	default:
		return PcapPacket{}, fmt.Errorf("不支持的链路层类型: %d", linkType)
	}

	if len(data) < ipOffset+20 {
		return PcapPacket{}, fmt.Errorf("IP 头过短")
	}

	// IP 头
	ipVersion := data[ipOffset] >> 4
	var srcIP, dstIP string
	var proto byte
	var ipHdrLen int

	if ipVersion == 4 {
		ipHdrLen = int(data[ipOffset]&0x0f) * 4
		if len(data) < ipOffset+ipHdrLen {
			return PcapPacket{}, fmt.Errorf("IPv4 头不完整")
		}
		srcIP = net.IP(data[ipOffset+12 : ipOffset+16]).String()
		dstIP = net.IP(data[ipOffset+16 : ipOffset+20]).String()
		proto = data[ipOffset+9]
	} else {
		return PcapPacket{}, fmt.Errorf("不支持的 IP 版本: %d", ipVersion)
	}

	transportOffset := ipOffset + ipHdrLen
	if len(data) < transportOffset+8 {
		return PcapPacket{}, fmt.Errorf("传输层头过短")
	}

	pkt := PcapPacket{
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Raw:       data[transportOffset:],
	}

	switch proto {
	case 17: // UDP
		pkt.Protocol = "UDP"
		pkt.SrcPort = int(binary.BigEndian.Uint16(data[transportOffset : transportOffset+2]))
		pkt.DstPort = int(binary.BigEndian.Uint16(data[transportOffset+2 : transportOffset+4]))
		// UDP 头长 8 字节
		if len(data) > transportOffset+8 {
			pkt.Raw = data[transportOffset+8:]
		}
	case 6: // TCP
		pkt.Protocol = "TCP"
		pkt.SrcPort = int(binary.BigEndian.Uint16(data[transportOffset : transportOffset+2]))
		pkt.DstPort = int(binary.BigEndian.Uint16(data[transportOffset+2 : transportOffset+4]))
		// TCP 头长度可变
		if len(data) > transportOffset+20 {
			tcpHdrLen := int(data[transportOffset+12]>>4) * 4
			if len(data) > transportOffset+tcpHdrLen {
				pkt.Raw = data[transportOffset+tcpHdrLen:]
			}
		}
	default:
		return PcapPacket{}, fmt.Errorf("不支持的协议: %d", proto)
	}

	return pkt, nil
}

// WritePcapFromCaptured 将捕获的 SIP 报文列表写入 pcap 格式字节。
// 生成标准的 libpcap 文件，可用 Wireshark 打开。
// 链路层使用 Raw IP (linktype=228)，避免构造以太网帧。
func WritePcapFromCaptured(packets []CapturedPacket) []byte {
	buf := &bytes.Buffer{}

	// 全局头（24 字节）
	// magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=228 (LINKTYPE_RAW)
	binary.Write(buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	binary.Write(buf, binary.LittleEndian, uint16(2))     // version major
	binary.Write(buf, binary.LittleEndian, uint16(4))     // version minor
	binary.Write(buf, binary.LittleEndian, int32(0))      // thiszone
	binary.Write(buf, binary.LittleEndian, uint32(0))     // sigfigs
	binary.Write(buf, binary.LittleEndian, uint32(65535)) // snaplen
	binary.Write(buf, binary.LittleEndian, uint32(228))   // linktype=LINKTYPE_RAW

	for _, pkt := range packets {
		srcIP, srcPort := parseAddr(pkt.Src)
		dstIP, dstPort := parseAddr(pkt.Dst)
		if srcIP == nil {
			srcIP = net.ParseIP("127.0.0.1")
			srcPort = 5060
		}
		if dstIP == nil {
			dstIP = net.ParseIP("127.0.0.1")
			dstPort = 5060
		}

		// 构造 IP + UDP + payload
		protoByte := byte(17) // UDP
		if strings.ToLower(pkt.Proto) == "tcp" {
			protoByte = 6
		}

		var transport []byte
		if protoByte == 17 {
			// UDP 头（8 字节）
			udp := make([]byte, 8)
			binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
			binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
			binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(pkt.Raw)))
			binary.BigEndian.PutUint16(udp[6:8], 0) // checksum=0
			transport = append(udp, pkt.Raw...)
		} else {
			// TCP 头（20 字节最小）
			tcp := make([]byte, 20)
			binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
			binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
			binary.BigEndian.PutUint32(tcp[4:8], 0)       // seq
			binary.BigEndian.PutUint32(tcp[8:12], 0)      // ack
			tcp[12] = 0x50                                // data offset=5 (20 bytes)
			tcp[13] = 0x18                                // flags=PSH+ACK
			binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
			transport = append(tcp, pkt.Raw...)
		}

		// IPv4 头（20 字节）
		ipHdr := make([]byte, 20)
		ipHdr[0] = 0x45 // version=4, ihl=5
		ipHdr[1] = 0x00 // tos
		totalLen := 20 + len(transport)
		binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(ipHdr[4:6], 0) // identification
		binary.BigEndian.PutUint16(ipHdr[6:8], 0) // flags+fragment
		ipHdr[8] = 64                             // ttl
		ipHdr[9] = protoByte
		copy(ipHdr[12:16], srcIP.To4())
		copy(ipHdr[16:20], dstIP.To4())

		pktBytes := append(ipHdr, transport...)

		// 报文记录头（16 字节）
		ts := pkt.TS
		if ts.IsZero() {
			ts = time.Now()
		}
		binary.Write(buf, binary.LittleEndian, uint32(ts.Unix()))
		binary.Write(buf, binary.LittleEndian, uint32(ts.Nanosecond()/1000))
		binary.Write(buf, binary.LittleEndian, uint32(len(pktBytes)))
		binary.Write(buf, binary.LittleEndian, uint32(len(pktBytes)))

		buf.Write(pktBytes)
	}

	return buf.Bytes()
}

// parseAddr 解析 "host:port" 格式。
func parseAddr(addr string) (net.IP, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0
	}
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	return ip, port
}
