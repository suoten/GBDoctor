package sip

import (
	"fmt"
	"strings"
	"time"
)

// SendVoiceInvite 平台向设备发送语音对讲 INVITE 请求。
// 与视频点播不同，语音对讲使用 m=audio 和 a=sendrecv。
func (r *DeviceSideRole) SendVoiceInvite(deviceID, channelID string, mediaPort int, ssrc string) (*SipMessage, error) {
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
	platformIP := r.cfg.Host
	if platformIP == "0.0.0.0" || platformIP == "" {
		platformIP = "127.0.0.1"
	}

	sdp := BuildVoiceInviteSDP(channelID, platformIP, mediaPort, ssrc)

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

	// 先注册应答通道再发送报文，避免亚毫秒级往返中响应早于通道就绪而被丢弃。
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
		return nil, fmt.Errorf("发送语音对讲 INVITE 失败: %w", err)
	}
	r.ev.RecordOut(t.Protocol(), target, msg.Bytes())

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	for {
		select {
		case resp := <-respCh:
			if resp.StatusCode >= 100 && resp.StatusCode < 200 {
				continue // 跳过 100 Trying / 180 Ringing 等临时响应
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
			return nil, fmt.Errorf("等待语音对讲 INVITE 应答超时")
		case <-r.stopCh:
			return nil, fmt.Errorf("已停止")
		}
	}
}

// VoiceFactFromResponse 从语音对讲 INVITE 应答中提取事实。
func VoiceFactFromResponse(resp *SipMessage, channelID string) VoiceFact {
	fact := VoiceFact{
		ChannelID:  channelID,
		StatusCode: resp.StatusCode,
		TS:         time.Now(),
	}
	if resp.StatusCode == 200 && len(resp.Body) > 0 {
		sdp := ParseSDP(resp.BodyText())
		fact.SDP = sdp
		// 判断音频方向
		if sdp != nil {
			for key, val := range sdp.Attributes {
				if strings.EqualFold(key, "a") {
					switch strings.ToLower(val) {
					case "sendrecv":
						fact.Direction = "sendrecv"
					case "sendonly":
						fact.Direction = "sendonly"
					case "recvonly":
						fact.Direction = "recvonly"
					}
				}
			}
			if fact.Direction == "" {
				fact.Direction = "sendrecv" // 默认双向
			}
		}
	}
	return fact
}

// VoiceValidations 校验语音对讲 SDP 合规性。
func VoiceValidations(sdp *SDPInfo) []Deviation {
	var devs []Deviation
	if sdp == nil {
		devs = append(devs, Deviation{Kind: "voice_no_sdp", Detail: "语音对讲 200 OK 缺少 SDP"})
		return devs
	}

	// 语音对讲必须是 audio 类型
	if sdp.MediaType != "" && sdp.MediaType != "audio" {
		devs = append(devs, Deviation{
			Kind:   "voice_not_audio",
			Detail: fmt.Sprintf("语音对讲 SDP 媒体类型为 %s，应为 audio", sdp.MediaType),
		})
	}

	// 语音对讲应为 sendrecv（双向）
	foundSendRecv := false
	for _, val := range sdp.Attributes {
		if strings.EqualFold(val, "sendrecv") {
			foundSendRecv = true
			break
		}
	}
	if !foundSendRecv {
		devs = append(devs, Deviation{
			Kind:   "voice_not_sendrecv",
			Detail: "语音对讲 SDP 缺少 a=sendrecv，可能导致单向音频",
		})
	}

	// SSRC 校验
	if sdp.SSRC == "" {
		devs = append(devs, Deviation{
			Kind:   "voice_no_ssrc",
			Detail: "语音对讲 SDP 缺少 y= 字段（SSRC）",
		})
	}

	return devs
}
