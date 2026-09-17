package sip

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Register 执行注册流程（REGISTER → 401 → REGISTER(鉴权) → 200 OK）。
// 返回 (最终应答, 设备实际使用的鉴权算法, 错误)。
func (c *CameraSideRole) Register() (*SipMessage, string, error) {
	resp, err := c.sendRegister("")
	if err != nil {
		return nil, "", err
	}
	alg := AlgoMD5
	if resp.StatusCode == 401 {
		www := resp.Headers.Get("www-authenticate")
		alg = NormalizeAlgorithm(ParseAuthParams(www)["algorithm"])
		if alg == "" {
			alg = AlgoMD5
		}
		resp, err = c.sendRegister(www)
		if err != nil {
			return nil, alg, err
		}
	}
	return resp, alg, nil
}

// sendRegister 发送 REGISTER；wwwAuth 非空时依据该挑战携带 Authorization。
func (c *CameraSideRole) sendRegister(wwwAuth string) (*SipMessage, error) {
	local, err := c.localAddr()
	if err != nil {
		return nil, err
	}

	cseq := c.nextCSeq()
	callID := randToken(16)
	tag := randToken(8)
	branch := "z9hG4bK" + randToken(10)
	uri := "sip:" + c.cfg.ServerID

	msg := NewRequest("REGISTER", uri, callID, cseq)
	msg.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(c.cfg.Transport), local, branch))
	msg.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", c.cfg.DeviceID, c.cfg.ServerID, tag))
	msg.Headers.Set("To", fmt.Sprintf("<sip:%s@%s>", c.cfg.DeviceID, c.cfg.ServerID))
	msg.Headers.Set("Max-Forwards", "70")
	msg.Headers.Set("Contact", fmt.Sprintf("<sip:%s@%s>", c.cfg.DeviceID, local))
	msg.Headers.Set("Expires", strconv.Itoa(c.cfg.Expires))

	if wwwAuth != "" {
		auth, err := c.buildAuthorization(wwwAuth)
		if err != nil {
			return nil, err
		}
		msg.Headers.Set("Authorization", auth)
	}

	c.mu.Lock()
	c.lastSent = msg
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}
	if err := conn.WriteRaw(msg.Bytes()); err != nil {
		return nil, err
	}
	return c.awaitResponse(c.cfg.Timeout)
}

// localAddr 返回本端地址（UDP 使用出口 IP 便于 NAT 事实判定）。
func (c *CameraSideRole) localAddr() (string, error) {
	if err := c.Connect(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return "", fmt.Errorf("连接未建立")
	}
	local := c.conn.LocalAddr()
	if !strings.EqualFold(c.cfg.Transport, "tcp") {
		// UDP：以实际出口 IP 构造 sent-by，避免 [::] 触发误判 NAT
		if _, port, err := net.SplitHostPort(local); err == nil && port != "" {
			return net.JoinHostPort(OutboundIP(c.cfg.ServerAddr), port), nil
		}
	}
	return local, nil
}

// buildAuthorization 依据挑战参数计算 Authorization 头。
func (c *CameraSideRole) buildAuthorization(www string) (string, error) {
	p := ParseAuthParams(www)
	if p["nonce"] == "" {
		return "", fmt.Errorf("挑战缺少 nonce")
	}
	realm := p["realm"]
	nonce := p["nonce"]
	alg := NormalizeAlgorithm(p["algorithm"])
	if alg == "" {
		alg = AlgoMD5
	}
	uri := "sip:" + c.cfg.ServerID
	response := ComputeDigestResponse(c.cfg.DeviceID, realm, c.cfg.Password, "REGISTER", uri, nonce, "", "", "", alg)
	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s`,
		c.cfg.DeviceID, realm, nonce, uri, response, alg)
	c.mu.Lock()
	c.lastAuth = auth
	c.mu.Unlock()
	return auth, nil
}

// awaitResponse 读取响应（跳过 1xx 与不可解析报文）。
// 当 listener 运行时，从 respCh 获取响应（避免 UDP socket 竞争读取）。
// 当 listener 未运行时，直接从 conn 读取。
func (c *CameraSideRole) awaitResponse(timeout time.Duration) (*SipMessage, error) {
	c.mu.Lock()
	conn := c.conn
	respCh := c.respCh
	c.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}

	// 如果 listener 在运行，从 respCh 读取
	if respCh != nil {
		deadline := time.Now().Add(timeout)
		for {
			remain := time.Until(deadline)
			if remain <= 0 {
				return nil, fmt.Errorf("等待应答超时")
			}
			timer := time.NewTimer(remain)
			select {
			case resp := <-respCh:
				timer.Stop()
				if resp.StatusCode == 0 || resp.StatusCode == 100 {
					continue
				}
				return resp, nil
			case <-timer.C:
				return nil, fmt.Errorf("等待应答超时")
			}
		}
	}

	// listener 未运行，直接从 conn 读取
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, fmt.Errorf("等待应答超时")
		}
		resp, err := conn.ReadMsg(remain)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 0 || resp.StatusCode == 100 {
			continue
		}
		return resp, nil
	}
}

// KeepaliveXML 构造国标 Keepalive 报文体。
func KeepaliveXML(deviceID string, sn int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<Notify><CmdType>Keepalive</CmdType><SN>%d</SN><DeviceID>%s</DeviceID><Status>OK</Status></Notify>`, sn, deviceID)
}

// Keepalive 发送一次心跳并等待 200 OK。
func (c *CameraSideRole) Keepalive(sn int) (*SipMessage, error) {
	return c.SendMessage(KeepaliveXML(c.cfg.DeviceID, sn))
}

// SendMessage 发送国标 XML（心跳/目录应答/DeviceInfo/Alarm 等）并等待应答。
func (c *CameraSideRole) SendMessage(xmlBody string) (*SipMessage, error) {
	local, err := c.localAddr()
	if err != nil {
		return nil, err
	}
	cseq := c.nextCSeq()
	callID := randToken(16)
	tag := randToken(8)
	branch := "z9hG4bK" + randToken(10)
	uri := "sip:" + c.cfg.ServerID

	msg := NewRequest("MESSAGE", uri, callID, cseq)
	msg.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(c.cfg.Transport), local, branch))
	msg.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", c.cfg.DeviceID, c.cfg.ServerID, tag))
	msg.Headers.Set("To", fmt.Sprintf("<sip:%s@%s>", c.cfg.DeviceID, c.cfg.ServerID))
	msg.Headers.Set("Max-Forwards", "70")
	msg.Headers.Set("Contact", fmt.Sprintf("<sip:%s@%s>", c.cfg.DeviceID, local))
	msg.Headers.Set("Content-Type", "Application/MANSCDP+xml")
	msg.Body = []byte(xmlBody)

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}
	if err := conn.WriteRaw(msg.Bytes()); err != nil {
		return nil, err
	}
	return c.awaitResponse(c.cfg.Timeout)
}
