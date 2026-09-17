package sip

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// SDPInfo 为解析后的 SDP 媒体描述。
type SDPInfo struct {
	Version      string
	Origin       string
	SessionName  string
	ConnectionIP string
	IPAddress    string // c= 行 IP
	MediaType    string // video / audio
	Port         int
	Transport    string // RTP/AVP
	PayloadType  int
	SSRC         string // y= 字段（国标扩展）
	Subject      string // s= 字段
	Attributes   map[string]string
}

// InviteFact 为 INVITE 环节事实。
type InviteFact struct {
	DeviceID   string
	ChannelID  string
	StatusCode int
	SDP        *SDPInfo
	TS         time.Time
	ErrCode    string
	ErrDetail  string
}

// ParseSDP 从 SDP 文本解析媒体描述。
func ParseSDP(body string) *SDPInfo {
	sdp := &SDPInfo{Attributes: map[string]string{}}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if len(ln) < 2 || ln[1] != '=' {
			continue
		}
		prefix := ln[0]
		value := strings.TrimSpace(ln[2:])
		switch prefix {
		case 'v':
			sdp.Version = value
		case 'o':
			sdp.Origin = value
		case 's':
			sdp.SessionName = value
			sdp.Subject = value
		case 'c':
			sdp.ConnectionIP = value
			parts := strings.Fields(value)
			if len(parts) >= 3 {
				sdp.IPAddress = parts[2]
			}
		case 'm':
			// m=video 6000 RTP/AVP 96
			parts := strings.Fields(value)
			if len(parts) >= 4 {
				sdp.MediaType = parts[0]
				sdp.Port, _ = strconv.Atoi(parts[1])
				sdp.Transport = parts[2]
				sdp.PayloadType, _ = strconv.Atoi(parts[3])
			}
		case 'y':
			sdp.SSRC = value
		default:
			// 同前缀多行属性（如 a=rtpmap 与 a=sendrecv 并存）必须全部保留，
			// 相互覆盖会导致方向检测/加密检测失真
			if prev, ok := sdp.Attributes[string(prefix)]; ok {
				sdp.Attributes[string(prefix)] = prev + "\n" + value
			} else {
				sdp.Attributes[string(prefix)] = value
			}
		}
	}
	return sdp
}

// SDPValidations 校验 SDP 中的国标合规性问题。
func SDPValidations(sdp *SDPInfo) []Deviation {
	var devs []Deviation
	if sdp == nil {
		devs = append(devs, Deviation{Kind: "sdp_missing", Detail: "200 OK 应答缺少 SDP 报文体"})
		return devs
	}

	// y= 字段（国标 SSRC）必须存在
	if sdp.SSRC == "" {
		devs = append(devs, Deviation{Kind: "sdp_no_ssrc", Detail: "SDP 缺少 y= 字段（国标 SSRC 扩展），上级平台无法关联 RTP 流"})
	} else if len(sdp.SSRC) != 10 {
		devs = append(devs, Deviation{Kind: "sdp_ssrc_length", Detail: fmt.Sprintf("y= 字段长度=%d，国标要求 10 位: %s", len(sdp.SSRC), sdp.SSRC)})
	}

	// s= 字段不应为空
	if sdp.SessionName == "" {
		devs = append(devs, Deviation{Kind: "sdp_no_session_name", Detail: "SDP 缺少 s= 字段"})
	}

	// 媒体端口不应为 0
	if sdp.Port == 0 {
		devs = append(devs, Deviation{Kind: "sdp_port_zero", Detail: "SDP 媒体端口为 0，设备未分配媒体端口"})
	}

	// c= 行 IP 不应为私网地址（跨网段场景）
	if sdp.IPAddress != "" && isPrivateIP(sdp.IPAddress) {
		devs = append(devs, Deviation{Kind: "sdp_private_ip", Detail: fmt.Sprintf("SDP c= 行地址 %s 为私网地址，跨网段拉流可能不可达", sdp.IPAddress)})
	}

	return devs
}

// isPrivateIP 判断 IP 是否为私网/保留地址。
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsPrivate() || parsed.IsLoopback() {
		return true
	}
	// 100.64.0.0/10 运营商级 NAT (CGNAT)
	// net.ParseIP 返回 16 字节，IPv4 地址存储在后 4 字节 [12:16]
	if v4 := parsed.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

// SSRCFromYField 从 y= 字段解析 SSRC（10 位数字，前 1 位表示流方向）。
// 0=实时，1=历史，前 5-6 位为行政域码低位。
func SSRCFromYField(y string) string {
	if len(y) != 10 {
		return ""
	}
	for i := 0; i < len(y); i++ {
		if y[i] < '0' || y[i] > '9' {
			return ""
		}
	}
	return y
}

// BuildInviteSDP 构造平台侧 INVITE 请求的 SDP（模拟上级平台点播）。
func BuildInviteSDP(channelID, platformIP string, mediaPort int, ssrc string) string {
	return fmt.Sprintf("v=0\r\n"+
		"o=%s 0 0 IN IP4 %s\r\n"+
		"s=Play\r\n"+
		"c=IN IP4 %s\r\n"+
		"t=0 0\r\n"+
		"m=video %d RTP/AVP 96\r\n"+
		"a=rtpmap:96 PS/90000\r\n"+
		"a=recvonly\r\n"+
		"y=%s\r\n", channelID, platformIP, platformIP, mediaPort, ssrc)
}

// InviteFactFromResponse 从 INVITE 应答中提取事实。
func InviteFactFromResponse(resp *SipMessage, channelID string) InviteFact {
	fact := InviteFact{
		ChannelID:  channelID,
		StatusCode: resp.StatusCode,
		TS:         time.Now(),
	}
	if resp.StatusCode == 200 && len(resp.Body) > 0 {
		sdp := ParseSDP(resp.BodyText())
		fact.SDP = sdp
		// 执行 SDP 校验，将偏差记入 ErrDetail
		devs := SDPValidations(sdp)
		for _, d := range devs {
			if fact.ErrDetail != "" {
				fact.ErrDetail += "; "
			}
			fact.ErrDetail += d.Detail
		}
	}
	return fact
}

// SendInvite 平台向设备发送 INVITE 请求（点播）。
// 返回设备最终应答（自动跳过 100 Trying / 180 Ringing 等临时响应）。
func (r *DeviceSideRole) SendInvite(deviceID, channelID string, mediaPort int, ssrc string) (*SipMessage, error) {
	session, ok := r.Session(deviceID)
	if !ok {
		return nil, fmt.Errorf("设备 %s 未注册", deviceID)
	}

	callID := randToken(16)
	tag := randToken(8)
	branch := "z9hG4bK" + randToken(10)
	uri := "sip:" + channelID + "@" + r.cfg.ServerID
	localAddr := fmt.Sprintf("%s:%d", r.cfg.Host, r.LocalPort())
	cseq := r.nextPlatformCSeq()
	// SDP 中的媒体接收地址必须是对设备可达的本机出口 IP：
	// 监听 0.0.0.0 时若回退 127.0.0.1，真机会向自己推流，导致必然的“200 OK 但无流”误报。
	platformIP := r.cfg.Host
	if platformIP == "0.0.0.0" || platformIP == "" {
		platformIP = OutboundIP(session.LastRegisterAddr)
	}

	sdp := BuildInviteSDP(channelID, platformIP, mediaPort, ssrc)

	// Via 协议必须与会话实际传输一致，部分设备按 Via 协议回送响应
	viaProto := "UDP"
	if strings.EqualFold(session.Transport, "tcp") {
		viaProto = "TCP"
	}

	msg := NewRequest("INVITE", uri, callID, cseq)
	msg.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", viaProto, localAddr, branch))
	msg.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", r.cfg.ServerID, r.cfg.ServerID, tag))
	msg.Headers.Set("To", fmt.Sprintf("<sip:%s@%s>", channelID, r.cfg.ServerID))
	msg.Headers.Set("Max-Forwards", "70")
	msg.Headers.Set("Contact", fmt.Sprintf("<sip:%s@%s>", r.cfg.ServerID, localAddr))
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Headers.Set("Subject", fmt.Sprintf("%s:0,%s:0", channelID, channelID))
	msg.Body = []byte(sdp)

	t := r.transportFor(session.Transport)
	if t == nil {
		return nil, fmt.Errorf("传输层不可用")
	}
	target := session.LastRegisterAddr

	// 关键：先注册应答通道再发送报文。
	// UDP 往返亚毫秒级，若先发送后注册，设备响应会在通道就绪前到达并被丢弃，
	// 导致本端白等超时、误报“点播失败”。
	respCh := make(chan *SipMessage, 4)
	r.mu.Lock()
	if r.pendingInvites == nil {
		r.pendingInvites = map[string]chan *SipMessage{}
	}
	r.pendingInvites[callID] = respCh
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pendingInvites, callID)
		r.mu.Unlock()
	}()

	if err := t.Send(msg.Bytes(), target); err != nil {
		return nil, fmt.Errorf("发送 INVITE 失败: %w", err)
	}
	r.ev.RecordOut(t.Protocol(), target, msg.Bytes())

	// 同时需要处理 ACK
	// 对于 200 OK，需要发送 ACK
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	// 循环跳过临时响应（1xx），只把最终响应（≥200）交给调用方。
	// 绝大多数摄像头收到 INVITE 后会先回 100 Trying 或 180 Ringing。
	for {
		select {
		case resp := <-respCh:
			if resp.StatusCode >= 100 && resp.StatusCode < 200 {
				continue // 临时响应，继续等待最终应答
			}
			if resp.StatusCode == 200 {
				// 发送 ACK
				ack := NewRequest("ACK", uri, callID, cseq)
				ack.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", viaProto, localAddr, branch))
				ack.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", r.cfg.ServerID, r.cfg.ServerID, tag))
				ack.Headers.Set("To", resp.Headers.Get("to"))
				ack.Headers.Set("Max-Forwards", "70")
				_ = t.Send(ack.Bytes(), target)
				r.ev.RecordOut(t.Protocol(), target, ack.Bytes())
			}
			return resp, nil
		case <-timer.C:
			return nil, fmt.Errorf("等待 INVITE 应答超时")
		case <-r.stopCh:
			return nil, fmt.Errorf("已停止")
		}
	}
}

// SendBye 平台向设备发送 BYE 请求（结束点播会话，停止媒体流）。
// 点播测试结束后必须挂断，否则设备会持续推流，占用编码资源，
// 并导致随后的重复体检因并发流数耗尽被拒（486），产生假故障。
func (r *DeviceSideRole) SendBye(deviceID, channelID string) error {
	session, ok := r.Session(deviceID)
	if !ok {
		return fmt.Errorf("设备 %s 未注册", deviceID)
	}

	callID := randToken(16)
	tag := randToken(8)
	branch := "z9hG4bK" + randToken(10)
	uri := "sip:" + channelID + "@" + r.cfg.ServerID
	localAddr := fmt.Sprintf("%s:%d", r.cfg.Host, r.LocalPort())
	cseq := r.nextPlatformCSeq()

	viaProto := "UDP"
	if strings.EqualFold(session.Transport, "tcp") {
		viaProto = "TCP"
	}

	msg := NewRequest("BYE", uri, callID, cseq)
	msg.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", viaProto, localAddr, branch))
	msg.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", r.cfg.ServerID, r.cfg.ServerID, tag))
	msg.Headers.Set("To", fmt.Sprintf("<sip:%s@%s>", channelID, r.cfg.ServerID))
	msg.Headers.Set("Max-Forwards", "70")

	t := r.transportFor(session.Transport)
	if t == nil {
		return fmt.Errorf("传输层不可用")
	}
	target := session.LastRegisterAddr
	if err := t.Send(msg.Bytes(), target); err != nil {
		return fmt.Errorf("发送 BYE 失败: %w", err)
	}
	r.ev.RecordOut(t.Protocol(), target, msg.Bytes())
	return nil
}
