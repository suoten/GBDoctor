package sip

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CameraHandler 为模拟摄像头入站请求处理器。
type CameraHandler func(msg *SipMessage, src string) (response *SipMessage)

// CameraListener 为模拟摄像头入站监听器。
// 在 CameraSideRole 的 UDP 连接上启动后台 goroutine，
// 处理平台发来的 MESSAGE（Catalog/DeviceInfo 查询）和 INVITE（点播）请求。
type CameraListener struct {
	cam      *CameraSideRole
	handlers map[string]CameraHandler // 按 Method 路由
	mu       sync.Mutex
	started  bool
	stopCh   chan struct{}

	// RTP 发送器（INVITE 200 OK 后自动发送模拟 RTP 流）
	rtpSender *MockRTPSender

	// 自动应答开关
	autoAnswerCatalog    bool
	autoAnswerDeviceInfo bool
	autoAnswerInvite     bool

	// 收到入站请求事实
	onInboundRequest func(msg *SipMessage, src string)
}

// NewCameraListener 创建模拟摄像头入站监听器。
func NewCameraListener(cam *CameraSideRole) *CameraListener {
	cl := &CameraListener{
		cam:                  cam,
		handlers:             map[string]CameraHandler{},
		stopCh:               make(chan struct{}),
		autoAnswerCatalog:    true,
		autoAnswerDeviceInfo: true,
		autoAnswerInvite:     true,
	}
	cl.registerDefaults()
	return cl
}

// OnInboundRequest 注册入站请求事实回调。
func (cl *CameraListener) OnInboundRequest(fn func(msg *SipMessage, src string)) {
	cl.onInboundRequest = fn
}

// SetAutoAnswer 设置自动应答开关。
func (cl *CameraListener) SetAutoAnswer(catalog, deviceInfo, invite bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.autoAnswerCatalog = catalog
	cl.autoAnswerDeviceInfo = deviceInfo
	cl.autoAnswerInvite = invite
}

// Start 启动监听。
func (cl *CameraListener) Start() error {
	cl.mu.Lock()
	if cl.started {
		cl.mu.Unlock()
		return nil
	}
	cl.started = true
	cl.mu.Unlock()

	go cl.listenLoop()
	return nil
}

// Stop 停止监听。
func (cl *CameraListener) Stop() {
	cl.mu.Lock()
	if !cl.started {
		cl.mu.Unlock()
		return
	}
	cl.started = false
	close(cl.stopCh)
	cl.mu.Unlock()
}

// listenLoop 监听入站报文（唯一读取者）。
// 读到请求报文 → handleInbound 处理。
// 读到响应报文 → 转发到 respCh 供 awaitResponse 获取。
func (cl *CameraListener) listenLoop() {
	for {
		select {
		case <-cl.stopCh:
			return
		default:
		}
		// 复用 CameraSideRole 的连接读取入站报文
		cl.cam.mu.Lock()
		conn := cl.cam.conn
		respCh := cl.cam.respCh
		cl.cam.mu.Unlock()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// 非阻塞读取：短超时轮询
		msg, err := conn.ReadMsg(500 * time.Millisecond)
		if err != nil {
			continue
		}
		if msg.IsRequest {
			// 入站请求（MESSAGE/INVITE/BYE），交给 handler 处理
			cl.handleInbound(msg)
		} else if msg.StatusCode > 0 && respCh != nil {
			// 响应报文，转发给 awaitResponse
			select {
			case respCh <- msg:
			default:
				// channel 满了，丢弃
			}
		}
	}
}

// handleInbound 处理入站请求。
func (cl *CameraListener) handleInbound(msg *SipMessage) {
	cl.mu.Lock()
	handler, ok := cl.handlers[msg.Method]
	cl.mu.Unlock()

	if ok && handler != nil {
		resp := handler(msg, "")
		if resp != nil {
			cl.cam.mu.Lock()
			conn := cl.cam.conn
			cl.cam.mu.Unlock()
			if conn != nil {
				_ = conn.WriteRaw(resp.Bytes())
			}
		}
	}

	if cl.onInboundRequest != nil {
		cl.onInboundRequest(msg, "")
	}
}

// registerDefaults 注册默认处理器。
func (cl *CameraListener) registerDefaults() {
	cl.handlers["MESSAGE"] = cl.handleMessage
	cl.handlers["INVITE"] = cl.handleInvite
	cl.handlers["BYE"] = cl.handleBye
}

// handleMessage 处理平台发来的 MESSAGE（Catalog 查询、DeviceInfo 查询等）。
func (cl *CameraListener) handleMessage(msg *SipMessage, src string) *SipMessage {
	body := msg.BodyText()
	cmdType := strings.ToLower(XMLTagValue(body, "CmdType"))

	// 回 200 OK
	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+randToken(8))

	// 自动应答 Catalog 查询
	if cl.autoAnswerCatalog && cmdType == "catalog" {
		deviceID := XMLTagValue(body, "DeviceID")
		if deviceID == "" {
			deviceID = cl.cam.cfg.DeviceID
		}
		catalogXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>Catalog</CmdType>
<SN>%s</SN>
<DeviceID>%s</DeviceID>
<Result>OK</Result>
<SumNum>2</SumNum>
<Item>
<DeviceID>34020000001310000001</DeviceID>
<Name>前门摄像头</Name>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD</Model>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
<Item>
<DeviceID>34020000001310000002</DeviceID>
<Name>后门摄像头</Name>
<Manufacturer>Dahua</Manufacturer>
<Model>IPC-HFW</Model>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
</Response>`, XMLTagValue(body, "SN"), deviceID)
		go func() {
			time.Sleep(100 * time.Millisecond)
			cl.cam.SendMessage(catalogXML)
		}()
	}

	// 自动应答 DeviceInfo 查询
	if cl.autoAnswerDeviceInfo && cmdType == "deviceinfo" {
		deviceID := XMLTagValue(body, "DeviceID")
		if deviceID == "" {
			deviceID = cl.cam.cfg.DeviceID
		}
		diXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>%s</SN>
<DeviceID>%s</DeviceID>
<Result>OK</Result>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD2T46</Model>
<FirmwareVersion>V5.7.3</FirmwareVersion>
<DeviceName>测试摄像头01</DeviceName>
</Response>`, XMLTagValue(body, "SN"), deviceID)
		go func() {
			time.Sleep(100 * time.Millisecond)
			cl.cam.SendMessage(diXML)
		}()
	}

	// 自动应答 RecordInfo 查询
	if cl.autoAnswerDeviceInfo && cmdType == "recordinfo" {
		deviceID := XMLTagValue(body, "DeviceID")
		if deviceID == "" {
			deviceID = cl.cam.cfg.DeviceID
		}
		startTime := XMLTagValue(body, "StartTime")
		endTime := XMLTagValue(body, "EndTime")
		recXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>%s</SN>
<DeviceID>%s</DeviceID>
<Name>测试摄像头01</Name>
<SumNum>1</SumNum>
<Item>
<DeviceID>%s</DeviceID>
<Name>录像段1</Name>
<FilePath>/record/001.mp4</FilePath>
<StartTime>%s</StartTime>
<EndTime>%s</EndTime>
</Item>
</Response>`, XMLTagValue(body, "SN"), deviceID, deviceID, startTime, endTime)
		go func() {
			time.Sleep(100 * time.Millisecond)
			cl.cam.SendMessage(recXML)
		}()
	}

	// 自动应答 Alarm 订阅
	if cl.autoAnswerDeviceInfo && cmdType == "alarm" {
		deviceID := XMLTagValue(body, "DeviceID")
		if deviceID == "" {
			deviceID = cl.cam.cfg.DeviceID
		}
		// 报警订阅是 Subscribe 请求，回 200 OK 即可
		// 同时主动发送一条模拟报警通知
		almXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Notify>
<CmdType>Alarm</CmdType>
<SN>%s</SN>
<DeviceID>%s</DeviceID>
<AlarmMethod>5</AlarmMethod>
<AlarmType>1</AlarmType>
<AlarmTime>%s</AlarmTime>
<Description>移动侦测报警</Description>
<Longitude>116.3974</Longitude>
<Latitude>39.9093</Latitude>
</Notify>`, XMLTagValue(body, "SN"), deviceID, time.Now().Format("2006-01-02 15:04:05"))
		go func() {
			time.Sleep(100 * time.Millisecond)
			cl.cam.SendMessage(almXML)
		}()
	}

	return resp
}

// handleInvite 处理平台发来的 INVITE（点播/语音对讲请求）。
// 自动回复 200 OK 携带 SDP，并启动 RTP 发送。
func (cl *CameraListener) handleInvite(msg *SipMessage, src string) *SipMessage {
	if !cl.autoAnswerInvite {
		return CreateResponse(msg, 486, "Busy Here")
	}

	// 解析平台 SDP
	platformSDP := ParseSDP(msg.BodyText())

	// 判断是视频点播还是语音对讲（通过 SDP 中的 m= 行）
	isVoice := platformSDP != nil && platformSDP.MediaType == "audio"

	// 构造设备侧 SDP 应答
	localIP := "127.0.0.1"
	if cl.cam.conn != nil {
		localAddr := cl.cam.conn.LocalAddr()
		if host, _, err := net.SplitHostPort(localAddr); err == nil && host != "" && host != "::" && host != "0.0.0.0" {
			localIP = host
		}
		// 如果是 IPv6 回环，转为 IPv4
		if localIP == "[::1]" || localIP == "::1" {
			localIP = "127.0.0.1"
		}
	}

	// 使用平台 SDP 中的端口或默认 6000
	mediaPort := 6000
	if platformSDP != nil && platformSDP.Port > 0 {
		mediaPort = platformSDP.Port + 2 // 设备端口通常偏移
	}

	ssrc := "0100000001"
	if platformSDP != nil && platformSDP.SSRC != "" {
		ssrc = platformSDP.SSRC
	}

	var deviceSDP string
	if isVoice {
		// 语音对讲: m=audio, a=sendrecv
		deviceSDP = fmt.Sprintf("v=0\r\n"+
			"o=%s 0 0 IN IP4 %s\r\n"+
			"s=Talk\r\n"+
			"c=IN IP4 %s\r\n"+
			"t=0 0\r\n"+
			"m=audio %d RTP/AVP 8\r\n"+
			"a=rtpmap:8 PCMA/8000\r\n"+
			"a=sendrecv\r\n"+
			"y=%s\r\n", cl.cam.cfg.DeviceID, localIP, localIP, mediaPort, ssrc)
	} else {
		// 视频点播: m=video, a=sendonly
		deviceSDP = fmt.Sprintf("v=0\r\n"+
			"o=%s 0 0 IN IP4 %s\r\n"+
			"s=Play\r\n"+
			"c=IN IP4 %s\r\n"+
			"t=0 0\r\n"+
			"m=video %d RTP/AVP 96\r\n"+
			"a=rtpmap:96 PS/90000\r\n"+
			"a=sendonly\r\n"+
			"y=%s\r\n", cl.cam.cfg.DeviceID, localIP, localIP, mediaPort, ssrc)
	}

	resp := CreateResponse(msg, 200, "")
	resp.Headers.Set("To", msg.Headers.Get("to")+";tag="+randToken(8))
	resp.Headers.Set("Content-Type", "application/sdp")
	resp.Body = []byte(deviceSDP)

	// 启动 RTP 发送（向平台媒体端口发送模拟 RTP 流）
	if platformSDP != nil && platformSDP.IPAddress != "" && platformSDP.Port > 0 {
		target := fmt.Sprintf("%s:%d", platformSDP.IPAddress, platformSDP.Port)
		ssrcNum, _ := strconv.ParseUint(ssrc, 10, 32)
		cl.rtpSender = NewMockRTPSender(target, uint32(ssrcNum))
		go cl.rtpSender.Start(10 * time.Second) // 发送 10 秒
	}

	return resp
}

// handleBye 处理 BYE 请求。
func (cl *CameraListener) handleBye(msg *SipMessage, src string) *SipMessage {
	if cl.rtpSender != nil {
		cl.rtpSender.Stop()
	}
	return CreateResponse(msg, 200, "")
}

// MockRTPSender 模拟摄像头发送 RTP 流。
type MockRTPSender struct {
	target    string
	conn      *net.UDPConn
	ssrc      uint32
	seq       uint16
	timestamp uint32
	stopCh    chan struct{}
	mu        sync.Mutex
	started   bool
}

// NewMockRTPSender 创建模拟 RTP 发送器。
func NewMockRTPSender(target string, ssrc uint32) *MockRTPSender {
	return &MockRTPSender{
		target: target,
		ssrc:   ssrc,
		stopCh: make(chan struct{}),
	}
}

// Start 开始发送 RTP 流，持续指定时长。
func (s *MockRTPSender) Start(duration time.Duration) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
	}()

	raddr, err := net.ResolveUDPAddr("udp", s.target)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer conn.Close()
	s.conn = conn

	// PS 负载模拟（1400 字节）
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	ticker := time.NewTicker(40 * time.Millisecond) // 25fps
	defer ticker.Stop()

	timer := time.NewTimer(duration)
	defer timer.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			return
		case <-ticker.C:
			s.seq++
			s.timestamp += 3600 // 90kHz / 25fps = 3600

			pkt := s.buildRTPPacket(payload)
			if _, err := conn.Write(pkt); err != nil {
				return
			}
		}
	}
}

// buildRTPPacket 构造 RTP 包。
func (s *MockRTPSender) buildRTPPacket(payload []byte) []byte {
	header := make([]byte, 12)
	header[0] = 0x80 // V=2, P=0, X=0, CC=0
	header[1] = 0x60 // M=0, PT=96
	header[2] = byte(s.seq >> 8)
	header[3] = byte(s.seq)
	header[4] = byte(s.timestamp >> 24)
	header[5] = byte(s.timestamp >> 16)
	header[6] = byte(s.timestamp >> 8)
	header[7] = byte(s.timestamp)
	header[8] = byte(s.ssrc >> 24)
	header[9] = byte(s.ssrc >> 16)
	header[10] = byte(s.ssrc >> 8)
	header[11] = byte(s.ssrc)

	return append(header, payload...)
}

// Stop 停止发送。
func (s *MockRTPSender) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}
