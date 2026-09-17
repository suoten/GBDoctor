package sip

import (
	"strconv"
	"strings"
	"time"
)

// Start 启动监听（UDP 默认开，TCP 可选）。
func (r *DeviceSideRole) Start() error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = true
	r.mu.Unlock()

	udp := NewUDPTransport(r.cfg.Host, r.cfg.Port, 512)
	if err := udp.Start(); err != nil {
		r.mu.Lock()
		r.started = false
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.udp = udp
	r.mu.Unlock()
	go r.dispatch(udp, "udp")

	if r.cfg.ListenTCP {
		tcp := NewTCPTransport(r.cfg.Host, r.cfg.Port, 512)
		if err := tcp.Start(); err != nil {
			_ = udp.Close()
			r.mu.Lock()
			r.started = false
			r.udp = nil
			r.mu.Unlock()
			return err
		}
		r.mu.Lock()
		r.tcp = tcp
		r.mu.Unlock()
		go r.dispatch(tcp, "tcp")
	}
	return nil
}

// dispatch 消费传输层报文并分发。
func (r *DeviceSideRole) dispatch(t Transport, proto string) {
	for {
		select {
		case <-r.stopCh:
			return
		case pkt, ok := <-t.Packets():
			if !ok {
				return
			}
			// 捕获入站报文
			r.mu.Lock()
			if len(r.capturedPackets) < 10000 {
				r.capturedPackets = append(r.capturedPackets, CapturedPacket{
					TS:        pkt.TS,
					Direction: "in",
					Src:       pkt.Src,
					Proto:     proto,
					Raw:       append([]byte(nil), pkt.Raw...),
				})
			}
			r.mu.Unlock()
			r.ev.RecordIn(pkt)
			r.handlePacket(pkt, proto)
		}
	}
}

// handlePacket 解析并路由到注册/MESSAGE 处理。
func (r *DeviceSideRole) handlePacket(pkt Packet, proto string) {
	msg := Parse(pkt.Raw)
	if !msg.IsRequest && msg.StatusCode > 0 {
		// 响应报文：检查是否为 pending INVITE/MESSAGE 事务的应答
		callID := msg.CallID()
		r.mu.Lock()
		ch, ok := r.pendingInvites[callID]
		if !ok {
			ch, ok = r.pendingMessages[callID]
		}
		r.mu.Unlock()
		if ok {
			select {
			case ch <- msg:
			default:
			}
		}
		return // 平台侧其他响应不在本角色处理
	}
	switch msg.Method {
	case "REGISTER":
		r.handleRegister(msg, pkt, proto)
	case "MESSAGE":
		r.handleMessage(msg, pkt, proto)
	case "INVITE":
		r.handlePlatformInvite(msg, pkt, proto)
	case "BYE":
		r.handleBye(msg, pkt, proto)
	}
}

// send 以传输层发送报文（证据登记出站）。
func (r *DeviceSideRole) send(t Transport, msg *SipMessage, addr string) {
	if t == nil {
		return
	}
	raw := msg.Bytes()
	_ = t.Send(raw, addr)
	r.ev.RecordOut(t.Protocol(), addr, raw)
}

// transportFor 按协议取传输层。
func (r *DeviceSideRole) transportFor(proto string) Transport {
	if proto == "tcp" && r.tcp != nil {
		return r.tcp
	}
	if r.udp != nil {
		return r.udp
	}
	if r.tcp != nil {
		return r.tcp
	}
	return nil
}

// handleRegister 处理注册流程：401 质询 → 鉴权校验 → 200 OK / 再质询 / 注销。
func (r *DeviceSideRole) handleRegister(msg *SipMessage, pkt Packet, proto string) {
	t := r.transportFor(proto)
	deviceID := URIUser(msg.Headers.Get("from"))
	contact := msg.Headers.Get("contact")
	authHdr := msg.Headers.Get("authorization")

	expires := r.cfg.RegisterExpires
	if expHdr := msg.Headers.Get("expires"); expHdr != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(expHdr)); err == nil {
			expires = n
		}
	}
	if c := contact; c != "" {
		if idx := strings.Index(strings.ToLower(c), "expires="); idx >= 0 {
			rest := c[idx+len("expires="):]
			rest = strings.Split(rest, ";")[0]
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				expires = n
			}
		}
	}

	deviceIDValid := isValidGB20(deviceID)
	viaAddr := firstViaSentBy(msg)
	receivedAddr := pkt.Src
	natMismatch := natMismatched(viaAddr, receivedAddr)

	emit := func(kind, failKind, alg string) {
		r.fireRegister(RegisterFact{
			Kind:          kind,
			DeviceID:      deviceID,
			Source:        pkt.Src,
			Algorithm:     alg,
			DeclaredAlg:   NormalizeAlgorithm(ParseAuthParams(authHdr)["algorithm"]),
			Expires:       expires,
			ViaAddr:       viaAddr,
			ContactAddr:   contact,
			ReceivedAddr:  receivedAddr,
			NATMismatch:   natMismatch,
			DeviceIDValid: deviceIDValid,
			FailureKind:   failKind,
			MaxInSize:     r.ev.MaxInPacketSize(),
			TS:            time.Now(),
			Raw:           pkt.Raw,
		})
	}

	if expires == 0 {
		r.mu.Lock()
		delete(r.sessions, deviceID)
		r.mu.Unlock()
		resp := CreateResponse(msg, 200, "")
		r.send(t, resp, pkt.Src)
		emit("deregister", "", "")
		return
	}

	if authHdr == "" {
		chal := r.auth.NewChallenge(deviceID, r.cfg.Realm, r.cfg.ChallengeAlg)
		resp := CreateResponse(msg, 401, "")
		resp.Headers.Set("WWW-Authenticate", chal.HeaderValue())
		r.send(t, resp, pkt.Src)
		emit("challenge", "", "")
		return
	}

	ok, declaredAlg, failKind := r.auth.Verify(authHdr, "REGISTER", msg.URI, deviceID, r.cfg.Password)
	if !ok {
		chal := r.auth.NewChallenge(deviceID, r.cfg.Realm, r.cfg.ChallengeAlg)
		resp := CreateResponse(msg, 401, "")
		resp.Headers.Set("WWW-Authenticate", chal.HeaderValue())
		r.send(t, resp, pkt.Src)
		emit("auth_fail", failKind, declaredAlg)
		return
	}

	host, port := splitHostPort(pkt.Src)
	r.mu.Lock()
	s, existed := r.sessions[deviceID]
	if !existed {
		s = &RegisterSession{DeviceID: deviceID}
		r.sessions[deviceID] = s
	}
	s.Host, s.Port = host, port
	s.Transport = proto
	s.Algorithm = declaredAlg
	if s.Algorithm == "" {
		s.Algorithm = r.cfg.ChallengeAlg
	}
	s.RegisteredAt = time.Now()
	s.Expires = expires
	s.LastRegisterAddr = pkt.Src
	s.RegisterCount++
	r.mu.Unlock()

	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+StableToTag(msg.CallID(), msg.Headers.Get("cseq"), "REGISTER"))
	r.send(t, resp, pkt.Src)
	emit("registered", "", s.Algorithm)
}

// handleMessage 处理 MESSAGE（心跳/目录应答等），一律 200 OK。
func (r *DeviceSideRole) handleMessage(msg *SipMessage, pkt Packet, proto string) {
	t := r.transportFor(proto)
	body := msg.BodyText()
	cmdType := XMLTagValue(body, "CmdType")
	deviceID := URIUser(msg.Headers.Get("from"))

	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+StableToTag(msg.CallID(), msg.Headers.Get("cseq"), "MESSAGE"))
	r.send(t, resp, pkt.Src)

	r.fireMessage(MessageFact{
		DeviceID: deviceID,
		CmdType:  strings.ToLower(cmdType),
		SN:       XMLTagValue(body, "SN"),
		Body:     body,
		Source:   pkt.Src,
		TS:       time.Now(),
	})

	if strings.EqualFold(cmdType, "Keepalive") {
		r.fireKeepalive(KeepaliveFact{
			DeviceID: deviceID,
			Source:   pkt.Src,
			XML:      body,
			OK:       true,
			TS:       time.Now(),
		})
		r.mu.Lock()
		if s, ok := r.sessions[deviceID]; ok {
			s.LastKeepaliveAt = time.Now()
			s.KeepaliveCount++
		}
		r.mu.Unlock()
	}

	// 目录应答：CmdType=Catalog
	if strings.EqualFold(cmdType, "Catalog") {
		fact := ParseCatalogResponse(body)
		fact.DeviceID = deviceID
		fact.Source = pkt.Src
		r.fireCatalog(fact)
	}

	// 设备信息应答：CmdType=DeviceInfo
	if strings.EqualFold(cmdType, "DeviceInfo") {
		fact := ParseDeviceInfoResponse(body)
		fact.DeviceID = deviceID
		fact.Source = pkt.Src
		r.fireDeviceInfo(fact)
	}

	// 报警通知：CmdType=Alarm
	if strings.EqualFold(cmdType, "Alarm") {
		fact := ParseAlarmNotification(body)
		fact.DeviceID = deviceID
		fact.Source = pkt.Src
		r.fireAlarm(fact)
	}

	// 录像检索应答：CmdType=RecordInfo
	if strings.EqualFold(cmdType, "RecordInfo") {
		fact := ParseRecordInfoResponse(body)
		fact.DeviceID = deviceID
		fact.Source = pkt.Src
		r.fireRecordInfo(fact)
	}
}

// handlePlatformInvite 处理来自设备侧的 INVITE 请求（语音对讲等场景）。
func (r *DeviceSideRole) handlePlatformInvite(msg *SipMessage, pkt Packet, proto string) {
	t := r.transportFor(proto)
	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+StableToTag(msg.CallID(), msg.Headers.Get("cseq"), "INVITE"))
	r.send(t, resp, pkt.Src)
}

// Cleanup 幂等清理（关闭传输、清空会话），异常路径亦可调用。
func (r *DeviceSideRole) Cleanup() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	r.started = false
	close(r.stopCh)
	udp, tcp := r.udp, r.tcp
	r.udp, r.tcp = nil, nil
	r.sessions = map[string]*RegisterSession{}
	r.mu.Unlock()
	if udp != nil {
		_ = udp.Close()
	}
	if tcp != nil {
		_ = tcp.Close()
	}
}

// handleBye 处理设备的 BYE 请求（停止媒体流），回 200 OK。
func (r *DeviceSideRole) handleBye(msg *SipMessage, pkt Packet, proto string) {
	t := r.transportFor(proto)
	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+StableToTag(msg.CallID(), msg.Headers.Get("cseq"), "BYE"))
	r.send(t, resp, pkt.Src)
}

// firstViaSentBy 提取首个 Via 的 sent-by 地址（"ip:port"）。
func firstViaSentBy(msg *SipMessage) string {
	via := msg.Headers.Get("via")
	if via == "" {
		return ""
	}
	if i := strings.Index(via, " "); i >= 0 {
		via = strings.TrimSpace(via[i+1:])
	}
	if i := strings.Index(via, ";"); i >= 0 {
		via = via[:i]
	}
	return strings.TrimSpace(via)
}

// natMismatched 判断 Via sent-by 与实际来源是否不一致（NAT 判据）。
func natMismatched(viaAddr, receivedAddr string) bool {
	if viaAddr == "" || receivedAddr == "" {
		return false
	}
	vh, vp := splitHostPort(viaAddr)
	rh, rp := splitHostPort(receivedAddr)
	if vh != "" && rh != "" && !sameHost(vh, rh) {
		return true
	}
	return vp != 0 && rp != 0 && vp != rp
}

func sameHost(a, b string) bool {
	a = strings.ToLower(strings.Trim(a, "[]"))
	b = strings.ToLower(strings.Trim(b, "[]"))
	if a == b {
		return true
	}
	if (a == "127.0.0.1" || a == "::1") && (b == "127.0.0.1" || b == "::1") {
		return true
	}
	return false
}

func splitHostPort(addr string) (string, int) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, 0
	}
	host := strings.Trim(addr[:i], "[]")
	port, _ := strconv.Atoi(addr[i+1:])
	return host, port
}

// isValidGB20 宽松校验 20 位数字编码。
func isValidGB20(code string) bool {
	if len(code) != 20 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// XMLTagValue 提取 XML 首个标签文本值（宽松、大小写不敏感）。
func XMLTagValue(body, tag string) string {
	if body == "" || tag == "" {
		return ""
	}
	lower := strings.ToLower(body)
	needle := "<" + strings.ToLower(tag) + ">"
	i := strings.Index(lower, needle)
	if i < 0 {
		return ""
	}
	rest := body[i+len(needle):]
	j := strings.Index(strings.ToLower(rest), "</"+strings.ToLower(tag)+">")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}
