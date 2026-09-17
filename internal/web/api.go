package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/netdiag"
	"gbdoctor/internal/report"
	"gbdoctor/internal/rules"
	"gbdoctor/internal/sip"
)

// Server 为 Web UI 服务器。
type Server struct {
	mu         sync.Mutex
	role       *sip.DeviceSideRole
	ruleEngine *sip.RuleEngine
	hub        *Hub
	version    string
	reports    map[string]*diag.ReportData    // 内存存储历史报告
	reportDir  string                         // 报告文件目录
	cameras    map[string]*sip.CameraSideRole // 模拟设备（deviceID → camera）
}

// NewServer 创建 Web UI 服务器。
func NewServer(version string) *Server {
	re, _ := rules.NewEngineWithBuiltinRules()
	return &Server{
		ruleEngine: re,
		hub:        NewHub(),
		version:    version,
		reports:    make(map[string]*diag.ReportData),
		reportDir:  filepath.Join(os.TempDir(), "gbdoctor-reports"),
		cameras:    make(map[string]*sip.CameraSideRole),
	}
}

// Routes 返回路由配置。
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// API 路由
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/sipsim/start", s.handleSipSimStart)
	mux.HandleFunc("/api/sipsim/stop", s.handleSipSimStop)
	mux.HandleFunc("/api/simcam/start", s.handleSimCamStart)
	mux.HandleFunc("/api/simcam/stop", s.handleSimCamStop)
	mux.HandleFunc("/api/simcam/keepalive", s.handleSimCamKeepalive)
	mux.HandleFunc("/api/simcam/catalog", s.handleSimCamCatalog)
	mux.HandleFunc("/api/simcam/deviceinfo", s.handleSimCamDeviceInfo)
	mux.HandleFunc("/api/simcam/recordinfo", s.handleSimCamRecordInfo)
	mux.HandleFunc("/api/simcam/alarm", s.handleSimCamAlarm)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/selftest", s.handleSelftest)
	mux.HandleFunc("/api/platform", s.handlePlatform)
	mux.HandleFunc("/api/pcap", s.handlePcap)
	mux.HandleFunc("/api/pcap/live", s.handlePcapLive)
	mux.HandleFunc("/api/netdiag", s.handleNetdiag)
	mux.HandleFunc("/api/reports", s.handleReportList)
	mux.HandleFunc("/api/report/", s.handleReportGet)
	mux.HandleFunc("/api/troubleshoot", s.handleTroubleshoot)
	mux.HandleFunc("/api/quickstart", s.handleQuickStart)

	// WebSocket
	mux.HandleFunc("/ws", s.hub.ServeWS)

	// 静态文件（go:embed）
	mux.HandleFunc("/", s.handleStatic)

	return mux
}

// Start 启动 Web 服务器。
func (s *Server) Start(addr string) error {
	_ = os.MkdirAll(s.reportDir, 0755)
	return http.ListenAndServe(addr, s.Routes())
}

// ============ API 处理器 ============

// handleStatus 返回服务器状态。
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := map[string]interface{}{
		"version":     s.version,
		"rule_count":  0,
		"sipsim_up":   false,
		"device_list": []interface{}{},
	}

	if s.ruleEngine != nil {
		status["rule_count"] = s.ruleEngine.RuleCount()
	}
	if s.role != nil {
		status["sipsim_up"] = true
		status["sipsim_port"] = s.role.LocalPort()

		sessions := s.role.Sessions()
		devs := make([]map[string]interface{}, 0, len(sessions))
		for _, sess := range sessions {
			devs = append(devs, map[string]interface{}{
				"device_id":       sess.DeviceID,
				"algorithm":       sess.Algorithm,
				"expires":         sess.Expires,
				"register_count":  sess.RegisterCount,
				"keepalive_count": sess.KeepaliveCount,
				"last_keepalive":  sess.LastKeepaliveAt.Format("15:04:05"),
			})
		}
		status["device_list"] = devs

		// 报文捕获统计
		captured := s.role.CapturedPackets()
		inCount, outCount := 0, 0
		for _, c := range captured {
			if c.Direction == "in" {
				inCount++
			} else {
				outCount++
			}
		}
		status["capture_count"] = len(captured)
		status["capture_in"] = inCount
		status["capture_out"] = outCount

		// 模拟设备运行状态
		status["simcam_running"] = len(s.cameras) > 0
		if len(s.cameras) > 0 {
			for id := range s.cameras {
				status["simcam_device_id"] = id
				break
			}
		}
	}

	jsonResponse(w, http.StatusOK, status)
}

// handleSipSimStart 启动模拟上级平台。
func (s *Server) handleSipSimStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		ServerID  string `json:"server_id"`
		Password  string `json:"password"`
		Algorithm string `json:"algorithm"`
		UseTCP    bool   `json:"use_tcp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}

	// 补默认值
	if req.Host == "" {
		req.Host = "0.0.0.0"
	}
	if req.ServerID == "" {
		req.ServerID = "34020000002000000001"
	}
	if req.Password == "" {
		req.Password = "12345678"
	}
	if req.Algorithm == "" {
		req.Algorithm = "MD5"
	}

	s.mu.Lock()
	if s.role != nil {
		s.mu.Unlock()
		jsonError(w, http.StatusConflict, "模拟平台已在运行中")
		return
	}

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:         req.Host,
		Port:         req.Port,
		ServerID:     req.ServerID,
		Password:     req.Password,
		ChallengeAlg: req.Algorithm,
		ListenTCP:    req.UseTCP,
	})

	// 注册事件回调 → WebSocket 推送
	role.OnRegister(func(f sip.RegisterFact) {
		switch f.Kind {
		case "registered":
			s.hub.BroadcastLog("success", fmt.Sprintf("✅ 设备 %s 注册成功（算法=%s, Expires=%d）", f.DeviceID, f.Algorithm, f.Expires))
			if f.NATMismatch {
				s.hub.BroadcastLog("warn", fmt.Sprintf("⚠️ NAT 地址不匹配: Via=%s, 来源=%s", f.ViaAddr, f.ReceivedAddr))
			}
		case "challenge":
			s.hub.BroadcastLog("info", fmt.Sprintf("→ 401 质询 %s", f.DeviceID))
		case "auth_fail":
			s.hub.BroadcastLog("error", fmt.Sprintf("❌ 鉴权失败 %s（类别=%s）", f.DeviceID, f.FailureKind))
		case "deregister":
			s.hub.BroadcastLog("info", fmt.Sprintf("⚪ 设备 %s 注销", f.DeviceID))
		}
		s.hub.BroadcastStatus("session_update", nil)
	})
	role.OnKeepalive(func(f sip.KeepaliveFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("✅ 心跳 %s", f.DeviceID))
		s.hub.BroadcastStatus("session_update", nil)
	})
	role.OnCatalog(func(f sip.CatalogFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("✅ 目录应答 %s（通道数=%d）", f.DeviceID, len(f.Items)))
	})
	role.OnDeviceInfo(func(f sip.DeviceInfoFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("✅ 设备信息 %s（厂商=%s 型号=%s）", f.DeviceID, f.Manufacturer, f.Model))
	})
	role.OnAlarm(func(f sip.AlarmFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("✅ 报警通知 %s（描述=%s）", f.DeviceID, f.Description))
	})

	if err := role.Start(); err != nil {
		// 如果指定端口被占用，尝试用随机端口
		if req.Port != 0 && strings.Contains(err.Error(), "bind") {
			s.hub.BroadcastLog("warn", fmt.Sprintf("端口 %d 被占用，自动切换到随机端口", req.Port))
			role2 := sip.NewDeviceSideRole(sip.RoleConfig{
				Host:         req.Host,
				Port:         0,
				ServerID:     req.ServerID,
				Password:     req.Password,
				ChallengeAlg: req.Algorithm,
				ListenTCP:    req.UseTCP,
			})
			role2.OnRegister(func(f sip.RegisterFact) {
				switch f.Kind {
				case "registered":
					s.hub.BroadcastLog("success", fmt.Sprintf("设备 %s 注册成功（算法=%s, Expires=%d）", f.DeviceID, f.Algorithm, f.Expires))
					if f.NATMismatch {
						s.hub.BroadcastLog("warn", fmt.Sprintf("NAT 地址不匹配: Via=%s, 来源=%s", f.ViaAddr, f.ReceivedAddr))
					}
				case "challenge":
					s.hub.BroadcastLog("info", fmt.Sprintf("→ 401 质询 %s", f.DeviceID))
				case "auth_fail":
					s.hub.BroadcastLog("error", fmt.Sprintf("鉴权失败 %s（类别=%s）", f.DeviceID, f.FailureKind))
				case "deregister":
					s.hub.BroadcastLog("info", fmt.Sprintf("设备 %s 注销", f.DeviceID))
				}
				s.hub.BroadcastStatus("session_update", nil)
			})
			role2.OnKeepalive(func(f sip.KeepaliveFact) {
				s.hub.BroadcastLog("success", fmt.Sprintf("心跳 %s", f.DeviceID))
				s.hub.BroadcastStatus("session_update", nil)
			})
			role2.OnCatalog(func(f sip.CatalogFact) {
				s.hub.BroadcastLog("success", fmt.Sprintf("目录应答 %s（通道数=%d）", f.DeviceID, len(f.Items)))
			})
			role2.OnDeviceInfo(func(f sip.DeviceInfoFact) {
				s.hub.BroadcastLog("success", fmt.Sprintf("设备信息 %s（厂商=%s 型号=%s）", f.DeviceID, f.Manufacturer, f.Model))
			})
			role2.OnAlarm(func(f sip.AlarmFact) {
				s.hub.BroadcastLog("success", fmt.Sprintf("报警通知 %s（描述=%s）", f.DeviceID, f.Description))
			})
			if err2 := role2.Start(); err2 != nil {
				s.mu.Unlock()
				jsonError(w, http.StatusInternalServerError, err2.Error())
				return
			}
			role = role2
		} else {
			s.mu.Unlock()
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.role = role
	port := role.LocalPort()
	s.mu.Unlock()

	s.hub.BroadcastLog("info", fmt.Sprintf("🚀 模拟上级平台已启动，监听 %s:%d", req.Host, port))
	s.hub.BroadcastStatus("sipsim_started", map[string]int{"port": port})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"port":      port,
		"server_id": req.ServerID,
		"message":   "模拟上级平台已启动",
	})
}

// handleSipSimStop 停止模拟上级平台。
func (s *Server) handleSipSimStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	s.mu.Lock()
	if s.role == nil {
		s.mu.Unlock()
		jsonError(w, http.StatusConflict, "模拟平台未运行")
		return
	}
	s.role.Cleanup()
	s.role = nil
	// 同时清理所有模拟设备
	for id, cam := range s.cameras {
		cam.Close()
		delete(s.cameras, id)
	}
	s.mu.Unlock()

	s.hub.BroadcastLog("info", "🛑 模拟上级平台已停止")
	s.hub.BroadcastStatus("sipsim_stopped", nil)

	jsonResponse(w, http.StatusOK, map[string]string{"message": "已停止"})
}

// handleSimCamStart 启动模拟摄像头并注册到已运行的模拟平台。
func (s *Server) handleSimCamStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		DeviceID  string `json:"device_id"`
		Password  string `json:"password"`
		Keepalive bool   `json:"auto_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}
	if req.Password == "" {
		req.Password = "12345678"
	}

	s.mu.Lock()
	role := s.role
	if role == nil {
		s.mu.Unlock()
		jsonError(w, http.StatusConflict, "模拟平台未启动，请先启动 SIP 仿真")
		return
	}
	if _, exists := s.cameras[req.DeviceID]; exists {
		s.mu.Unlock()
		jsonError(w, http.StatusConflict, "设备 "+req.DeviceID+" 已在运行中")
		return
	}
	port := role.LocalPort()
	serverID := role.ServerID()
	s.mu.Unlock()

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: "127.0.0.1:" + strconv.Itoa(port),
		ServerID:   serverID,
		DeviceID:   req.DeviceID,
		Password:   req.Password,
		Timeout:    5 * time.Second,
	})

	resp, alg, err := cam.Register()
	if err != nil {
		cam.Close()
		jsonError(w, http.StatusInternalServerError, "注册失败: "+err.Error())
		return
	}
	if resp.StatusCode != 200 {
		cam.Close()
		jsonError(w, http.StatusConflict, fmt.Sprintf("注册被拒绝: %d %s", resp.StatusCode, resp.ReasonPhrase))
		return
	}

	// 启动入站监听器：自动应答 Catalog/DeviceInfo/INVITE 等平台查询
	cam.StartListener()

	// 立刻发送一次心跳，确保体检引擎检查保活时 KeepaliveCount > 0
	if _, err := cam.Keepalive(1); err != nil {
		s.hub.BroadcastLog("warn", fmt.Sprintf("首次心跳发送失败 %s: %v", req.DeviceID, err))
	} else {
		s.hub.BroadcastLog("success", fmt.Sprintf("心跳已发送 %s", req.DeviceID))
	}

	s.mu.Lock()
	s.cameras[req.DeviceID] = cam
	s.mu.Unlock()

	s.hub.BroadcastLog("success", fmt.Sprintf("模拟设备 %s 已注册成功（算法=%s），监听器已启动", req.DeviceID, alg))
	s.hub.BroadcastStatus("session_update", nil)

	if req.Keepalive {
		go func() {
			sn := 1
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					sn++
					s.mu.Lock()
					c, ok := s.cameras[req.DeviceID]
					s.mu.Unlock()
					if !ok {
						return
					}
					if _, err := c.Keepalive(sn); err != nil {
						s.hub.BroadcastLog("error", fmt.Sprintf("心跳失败 %s: %v", req.DeviceID, err))
						return
					}
				}
			}
		}()
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"device_id": req.DeviceID,
		"algorithm": alg,
		"message":   "模拟设备已注册成功",
	})
}

// handleSimCamStop 停止模拟设备。
func (s *Server) handleSimCamStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	if ok {
		delete(s.cameras, req.DeviceID)
	}
	s.mu.Unlock()

	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}
	cam.Close()
	s.hub.BroadcastLog("info", "🛑 模拟设备 "+req.DeviceID+" 已停止")
	s.hub.BroadcastStatus("session_update", nil)

	jsonResponse(w, http.StatusOK, map[string]string{"message": "已停止"})
}

// handleSimCamKeepalive 发送心跳。
func (s *Server) handleSimCamKeepalive(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		SN       int    `json:"sn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	s.mu.Unlock()
	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}
	if req.SN == 0 {
		req.SN = 1
	}
	resp, err := cam.Keepalive(req.SN)
	if err != nil || resp.StatusCode != 200 {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("心跳失败: err=%v code=%d", err, resp.StatusCode))
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"device_id": req.DeviceID, "sn": req.SN, "code": resp.StatusCode})
}

// handleSimCamCatalog 模拟设备回复目录应答。
func (s *Server) handleSimCamCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	role := s.role
	s.mu.Unlock()
	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}

	if role != nil {
		_ = role.QueryCatalog(req.DeviceID)
	}

	catalogXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>Catalog</CmdType>
<SN>1001</SN>
<DeviceID>` + req.DeviceID + `</DeviceID>
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
</Response>`
	_, err := cam.SendMessage(catalogXML)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "发送失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "目录应答已发送"})
}

// handleSimCamDeviceInfo 模拟设备回复设备信息。
func (s *Server) handleSimCamDeviceInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	role := s.role
	s.mu.Unlock()
	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}

	if role != nil {
		_ = role.QueryDeviceInfo(req.DeviceID)
	}

	diXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>2001</SN>
<DeviceID>` + req.DeviceID + `</DeviceID>
<Result>OK</Result>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD2T46</Model>
<FirmwareVersion>V5.7.3</FirmwareVersion>
<DeviceName>测试摄像头01</DeviceName>
</Response>`
	_, err := cam.SendMessage(diXML)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "发送失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "设备信息已发送"})
}

// handleSimCamRecordInfo 模拟设备回复录像检索。
func (s *Server) handleSimCamRecordInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	role := s.role
	s.mu.Unlock()
	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}

	if role != nil {
		startTime := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
		endTime := time.Now().Format("2006-01-02 15:04:05")
		_ = role.QueryRecordInfo(req.DeviceID, startTime, endTime)
	}

	recXML := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>3001</SN>
<DeviceID>` + req.DeviceID + `</DeviceID>
<Name>测试摄像头01</Name>
<SumNum>1</SumNum>
<Item>
<DeviceID>` + req.DeviceID + `</DeviceID>
<Name>录像段1</Name>
<FilePath>/record/001.mp4</FilePath>
<StartTime>2026-09-16 08:00:00</StartTime>
<EndTime>2026-09-16 09:00:00</EndTime>
</Item>
</Response>`
	_, err := cam.SendMessage(recXML)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "发送失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "录像应答已发送"})
}

// handleSimCamAlarm 模拟设备发送报警通知。
func (s *Server) handleSimCamAlarm(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}

	s.mu.Lock()
	cam, ok := s.cameras[req.DeviceID]
	role := s.role
	s.mu.Unlock()
	if !ok {
		jsonError(w, http.StatusNotFound, "模拟设备 "+req.DeviceID+" 未运行")
		return
	}

	if role != nil {
		_ = role.SubscribeAlarm(req.DeviceID, 60)
	}

	almXML := `<?xml version="1.0" encoding="UTF-8"?>
<Notify>
<CmdType>Alarm</CmdType>
<SN>8001</SN>
<DeviceID>` + req.DeviceID + `</DeviceID>
<AlarmMethod>5</AlarmMethod>
<AlarmType>1</AlarmType>
<AlarmTime>2026-09-16 10:30:00</AlarmTime>
<Description>移动侦测报警</Description>
<Longitude>116.3974</Longitude>
<Latitude>39.9093</Latitude>
</Notify>`
	_, err := cam.SendMessage(almXML)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "发送失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "报警通知已发送"})
}

// handleSessions 返回已注册设备列表。
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role == nil {
		jsonResponse(w, http.StatusOK, []interface{}{})
		return
	}

	sessions := s.role.Sessions()
	devs := make([]map[string]interface{}, 0, len(sessions))
	for _, sess := range sessions {
		devs = append(devs, map[string]interface{}{
			"device_id":       sess.DeviceID,
			"algorithm":       sess.Algorithm,
			"expires":         sess.Expires,
			"register_count":  sess.RegisterCount,
			"keepalive_count": sess.KeepaliveCount,
			"last_keepalive":  sess.LastKeepaliveAt.Format("15:04:05"),
			"registered_at":   sess.RegisteredAt.Format("15:04:05"),
		})
	}

	jsonResponse(w, http.StatusOK, devs)
}

// handleCheck 对已注册设备执行全链路体检。
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		DeviceID       string `json:"device_id"`
		SkipCatalog    bool   `json:"skip_catalog"`
		SkipInvite     bool   `json:"skip_invite"`
		SkipDeviceInfo bool   `json:"skip_deviceinfo"`
		SkipPTZ        bool   `json:"skip_ptz"`
		SkipAlarm      bool   `json:"skip_alarm"`
		SkipRecord     bool   `json:"skip_record"`
		SkipVoice      bool   `json:"skip_voice"`
		SkipGB2022     bool   `json:"skip_gb2022"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}

	if req.DeviceID == "" {
		jsonError(w, http.StatusBadRequest, "device_id 必填")
		return
	}

	s.mu.Lock()
	role := s.role
	re := s.ruleEngine
	s.mu.Unlock()

	if role == nil {
		jsonError(w, http.StatusConflict, "模拟平台未启动，请先启动 SIP 仿真")
		return
	}

	// 检查设备是否已注册
	if _, ok := role.Session(req.DeviceID); !ok {
		jsonError(w, http.StatusConflict, "设备 "+req.DeviceID+" 未注册到模拟平台")
		return
	}

	// 异步执行体检
	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.hub.BroadcastLog("error", fmt.Sprintf("体检流程内部错误: %v", p))
			}
		}()
		s.hub.BroadcastLog("info", fmt.Sprintf("🔬 开始对设备 %s 执行全链路体检…", req.DeviceID))
		s.hub.BroadcastStatus("checking", req.DeviceID)

		engine := diag.NewEngine(role, re, diag.CheckConfig{
			DeviceID:       req.DeviceID,
			SkipCatalog:    req.SkipCatalog,
			SkipInvite:     req.SkipInvite,
			SkipDeviceInfo: req.SkipDeviceInfo,
			SkipPTZ:        req.SkipPTZ,
			SkipAlarm:      req.SkipAlarm,
			SkipRecord:     req.SkipRecord,
			SkipVoice:      req.SkipVoice,
			SkipGB2022:     req.SkipGB2022,
		})

		// 包装回调，推送每个环节完成事件
		// 引擎内部会注册 OnDeviceInfo / OnRecordInfo 等回调
		// 我们在引擎外部添加额外的回调来推送进度
		origOnDeviceInfo := role // 不覆盖已有回调，因为引擎会追加

		reportData := engine.Run()

		// 推送每个环节结果
		for _, stage := range reportData.Stages {
			s.hub.BroadcastStage(stage)
		}

		// 保存报告
		s.mu.Lock()
		s.reports[reportData.ReportID] = reportData
		s.mu.Unlock()

		// 生成 HTML 文件
		htmlPath := filepath.Join(s.reportDir, reportData.ReportID+".html")
		_ = report.GenerateHTMLFile(reportData, htmlPath)

		s.hub.BroadcastLog("info", fmt.Sprintf("📊 体检完成: 得分 %d/100, 问题 %d 个, 证据 %d 条",
			reportData.Score, len(reportData.AllIssues), reportData.EvidenceCount))
		s.hub.BroadcastDone(reportData.Score, reportData.Passed, reportData.ReportID, len(reportData.AllIssues))
		s.hub.BroadcastStatus("idle", nil)

		_ = origOnDeviceInfo
	}()

	jsonResponse(w, http.StatusAccepted, map[string]string{
		"message": "体检已开始，请通过 WebSocket 关注实时进度",
	})
}

// handleSelftest 本机回环自检。
func (s *Server) handleSelftest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.hub.BroadcastLog("error", fmt.Sprintf("本机自检内部错误: %v", p))
			}
		}()
		s.hub.BroadcastLog("info", "🔬 开始本机回环自检…")
		s.hub.BroadcastStatus("selftest", nil)

		role := sip.NewDeviceSideRole(sip.RoleConfig{
			Host:     "127.0.0.1",
			Port:     0,
			ServerID: "34020000002000000001",
			Password: "selftest",
		})
		if err := role.Start(); err != nil {
			s.hub.BroadcastError("模拟平台启动失败: " + err.Error())
			s.hub.BroadcastStatus("idle", nil)
			return
		}
		defer role.Cleanup()

		port := role.LocalPort()
		s.hub.BroadcastLog("info", fmt.Sprintf("✅ 模拟平台已启动 127.0.0.1:%d", port))

		cam := sip.NewCameraSideRole(sip.CameraConfig{
			ServerAddr: "127.0.0.1:" + strconv.Itoa(port),
			ServerID:   "34020000002000000001",
			DeviceID:   "34020000001320000001",
			Password:   "selftest",
			Timeout:    3 * time.Second,
		})
		defer cam.Close()

		// 注册
		resp, alg, err := cam.Register()
		if err != nil || resp.StatusCode != 200 {
			s.hub.BroadcastError(fmt.Sprintf("注册环节失败: err=%v code=%d", err, resp.StatusCode))
			s.hub.BroadcastStatus("idle", nil)
			return
		}
		s.hub.BroadcastLog("success", fmt.Sprintf("✅ 注册环节: 401 质询 → 鉴权 → 200 OK（算法 %s）", alg))

		// 心跳
		resp2, err := cam.Keepalive(1)
		if err != nil || resp2.StatusCode != 200 {
			s.hub.BroadcastError(fmt.Sprintf("保活环节失败: err=%v", err))
		} else {
			s.hub.BroadcastLog("success", "✅ 保活环节: MESSAGE Keepalive → 200 OK")
		}

		// 全链路体检
		re, _ := rules.NewEngineWithBuiltinRules()
		engine := diag.NewEngine(role, re, diag.CheckConfig{
			DeviceID:    "34020000001320000001",
			SkipCatalog: true,
			SkipInvite:  true,
			SkipRTP:     true,
		})
		reportData := engine.Run()

		for _, stage := range reportData.Stages {
			s.hub.BroadcastStage(stage)
		}

		s.mu.Lock()
		s.reports[reportData.ReportID] = reportData
		s.mu.Unlock()

		htmlPath := filepath.Join(s.reportDir, reportData.ReportID+".html")
		_ = report.GenerateHTMLFile(reportData, htmlPath)

		evCount := role.Evidence().Count()
		s.hub.BroadcastLog("info", fmt.Sprintf("✅ 证据链: %d 条证据（原文 + SHA-256 指纹 + 鉴权头脱敏）", evCount))
		s.hub.BroadcastDone(reportData.Score, reportData.Passed, reportData.ReportID, len(reportData.AllIssues))
		s.hub.BroadcastStatus("idle", nil)
	}()

	jsonResponse(w, http.StatusAccepted, map[string]string{
		"message": "自检已开始，请通过 WebSocket 关注实时进度",
	})
}

// handlePlatform 平台侧体检（模拟摄像头注册到真实上级平台）。
func (s *Server) handlePlatform(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		ServerAddr string `json:"server_addr"`
		ServerID   string `json:"server_id"`
		DeviceID   string `json:"device_id"`
		Password   string `json:"password"`
		Transport  string `json:"transport"`
		Timeout    string `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}

	if req.ServerAddr == "" {
		jsonError(w, http.StatusBadRequest, "server_addr 必填")
		return
	}

	// 补默认值
	if req.ServerID == "" {
		req.ServerID = "34020000002000000001"
	}
	if req.DeviceID == "" {
		req.DeviceID = "34020000001320000001"
	}
	if req.Password == "" {
		req.Password = "12345678"
	}
	if req.Transport == "" {
		req.Transport = "udp"
	}

	timeout := 15 * time.Second
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = d
		}
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.hub.BroadcastLog("error", fmt.Sprintf("平台侧体检内部错误: %v", p))
			}
		}()
		s.hub.BroadcastLog("info", fmt.Sprintf("🔬 平台侧体检: 目标 %s, 设备 %s", req.ServerAddr, req.DeviceID))
		s.hub.BroadcastStatus("platform_check", req.ServerAddr)

		cam := sip.NewCameraSideRole(sip.CameraConfig{
			ServerAddr: req.ServerAddr,
			ServerID:   req.ServerID,
			DeviceID:   req.DeviceID,
			Password:   req.Password,
			Transport:  req.Transport,
			Timeout:    5 * time.Second,
		})
		defer cam.Close()

		result := sip.CheckPlatform(cam, req.ServerID, timeout)

		s.hub.BroadcastLog("info", fmt.Sprintf("注册: %v (算法=%s)", result.RegisterOK, result.RegisterAlg))
		s.hub.BroadcastLog("info", fmt.Sprintf("心跳: %v", result.KeepaliveOK))
		s.hub.BroadcastLog("info", fmt.Sprintf("目录查询: %v", result.CatalogQueryOK))
		s.hub.BroadcastLog("info", fmt.Sprintf("设备信息: %v", result.DeviceInfoOK))
		s.hub.BroadcastLog("info", fmt.Sprintf("点播: %v", result.InviteOK))

		for _, fact := range result.Facts {
			s.hub.BroadcastLog("info", fact)
		}
		if len(result.Issues) > 0 {
			for _, iss := range result.Issues {
				s.hub.BroadcastLog("warn", fmt.Sprintf("[%s] %s", iss.Severity, iss.Title))
			}
		}

		s.hub.BroadcastStatus("idle", nil)
	}()

	jsonResponse(w, http.StatusAccepted, map[string]string{
		"message": "平台侧体检已开始",
	})
}

// handlePcap pcap 离线分析。
func (s *Server) handlePcap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	// 限制上传大小 50MB
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)

	data, err := readAll(r.Body, 50<<20)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "读取上传文件失败: "+err.Error())
		return
	}

	if len(data) == 0 {
		jsonError(w, http.StatusBadRequest, "文件为空")
		return
	}

	// 同步解析（pcap 分析很快）
	s.hub.BroadcastLog("info", fmt.Sprintf("🔬 pcap 分析: %d 字节", len(data)))

	packets, err := sip.ParsePcapFile(data)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "pcap 解析失败: "+err.Error())
		return
	}

	s.hub.BroadcastLog("info", fmt.Sprintf("解析报文: %d 个", len(packets)))

	result := sip.AnalyzePcap(packets, "upload.pcap")
	for _, fact := range result.Facts {
		s.hub.BroadcastLog("info", fact)
	}
	if len(result.Issues) > 0 {
		for _, iss := range result.Issues {
			level := "warn"
			if iss.Severity == sip.SeverityBlocking {
				level = "error"
			}
			s.hub.BroadcastLog(level, fmt.Sprintf("[%s] %s: %s", iss.Severity, iss.Title, iss.Explain))
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"packet_count": len(packets),
		"facts":        result.Facts,
		"issues":       result.Issues,
	})
}

// handlePcapLive 导出体检过程中内置捕获的 SIP 报文为 pcap 文件。
func (s *Server) handlePcapLive(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	role := s.role
	s.mu.Unlock()

	if role == nil {
		jsonError(w, http.StatusConflict, "模拟平台未启动，无捕获数据")
		return
	}

	captured := role.CapturedPackets()
	if len(captured) == 0 {
		jsonError(w, http.StatusNotFound, "暂无捕获数据，请先启动平台并执行体检")
		return
	}

	// HEAD 请求只返回统计
	if r.Method == "HEAD" {
		w.Header().Set("X-Capture-Count", strconv.Itoa(len(captured)))
		w.WriteHeader(http.StatusOK)
		return
	}

	pcapData := sip.WritePcapFromCaptured(captured)

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=gbdoctor-capture-%s.pcap", time.Now().Format("20060102-150405")))
	w.Header().Set("Content-Length", strconv.Itoa(len(pcapData)))
	w.Write(pcapData)
}

// handleNetdiag 网络诊断。
func (s *Server) handleNetdiag(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	var req struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}

	if req.Target == "" {
		jsonError(w, http.StatusBadRequest, "target 必填")
		return
	}
	if req.Port == 0 {
		req.Port = 5060
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.hub.BroadcastLog("error", fmt.Sprintf("网络诊断内部错误: %v", p))
			}
		}()
		s.hub.BroadcastLog("info", fmt.Sprintf("🔬 网络诊断: %s:%d", req.Target, req.Port))
		s.hub.BroadcastStatus("netdiag", req.Target)

		result := netdiag.RunNetworkDiagnosis(req.Target, req.Port)
		for _, c := range result.Conclusions {
			s.hub.BroadcastLog("info", c)
		}
		if len(result.Deviations) > 0 {
			s.hub.BroadcastLog("warn", fmt.Sprintf("发现 %d 个网络问题", len(result.Deviations)))
		} else {
			s.hub.BroadcastLog("success", "✅ 网络诊断通过")
		}

		s.hub.BroadcastStatus("idle", nil)
	}()

	jsonResponse(w, http.StatusAccepted, map[string]string{
		"message": "网络诊断已开始",
	})
}

// handleReportList 历史报告列表。
func (s *Server) handleReportList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := make([]map[string]interface{}, 0, len(s.reports))
	for _, rp := range s.reports {
		list = append(list, map[string]interface{}{
			"report_id":      rp.ReportID,
			"device_id":      rp.DeviceID,
			"score":          rp.Score,
			"passed":         rp.Passed,
			"start_time":     rp.StartTime.Format("2006-01-02 15:04:05"),
			"issue_count":    len(rp.AllIssues),
			"evidence_count": rp.EvidenceCount,
		})
	}

	jsonResponse(w, http.StatusOK, list)
}

// handleReportGet 获取单个体检报告。
func (s *Server) handleReportGet(w http.ResponseWriter, r *http.Request) {
	reportID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if reportID == "" {
		jsonError(w, http.StatusBadRequest, "缺少报告 ID")
		return
	}

	s.mu.Lock()
	rp, ok := s.reports[reportID]
	s.mu.Unlock()

	if !ok {
		jsonError(w, http.StatusNotFound, "报告不存在")
		return
	}

	// 返回 HTML 报告
	html, err := report.GenerateHTML(rp)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "报告生成失败: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleStatic 处理静态文件。
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	// 先尝试从 embed 读取
	data, err := staticFiles.ReadFile("web" + path)
	if err != nil {
		// SPA fallback：返回 index.html
		data, err = staticFiles.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}

	// 设置 Content-Type
	switch {
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(path, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	}

	w.Write(data)
}

// ============ 工具函数 ============

func jsonResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	jsonResponse(w, code, map[string]string{"error": msg})
}

func readAll(r interface{ Read([]byte) (int, error) }, max int) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		if len(buf) > max {
			return nil, fmt.Errorf("文件过大，超过 %d 字节限制", max)
		}
	}
	return buf, nil
}

// handleTroubleshoot 设备注册排查建议。
// 返回本机 IP、平台端口、常见排查清单。
func (s *Server) handleTroubleshoot(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	role := s.role
	s.mu.Unlock()

	result := map[string]interface{}{
		"platform_up": false,
		"tips":        []string{},
	}

	if role == nil {
		result["tips"] = []string{
			"平台未启动，请先点击「启动平台」",
		}
		jsonResponse(w, http.StatusOK, result)
		return
	}

	port := role.LocalPort()
	localIP := sip.OutboundIP("8.8.8.8:80")
	sessions := role.Sessions()

	result["platform_up"] = true
	result["platform_port"] = port
	result["local_ip"] = localIP
	result["device_count"] = len(sessions)

	tips := []string{
		fmt.Sprintf("本机 IP: %s（摄像头 SIP 服务器地址应填这个）", localIP),
		fmt.Sprintf("平台端口: %d（如果 5060 被占用会自动换端口，请确认摄像头填的是这个端口）", port),
	}

	if len(sessions) == 0 {
		tips = append(tips,
			"",
			"—— 设备注册不上来？逐项排查 ——",
			"1. 确认摄像头 SIP 服务器 IP 填的是本机 IP（上面显示的地址），不是 127.0.0.1",
			"2. 确认 SIP 端口填的是上面显示的端口（5060 被占用会自动换端口）",
			"3. 确认服务器编码与上方配置一致",
			"4. 确认鉴权密码与上方配置一致",
			"5. 确认摄像头与电脑在同一网段、互相 ping 得通",
			"6. 确认防火墙未拦截 UDP 5060 端口（Windows 防火墙可能默认拦截）",
			"7. 确认摄像头 GB28181 功能已启用（部分设备需要手动开启）",
			"8. 如果摄像头在其他网段，确认路由可达、NAT 不拦截",
			"",
			"—— 还可以用网络诊断工具排查 ——",
			"切到「网络诊断」tab，输入摄像头 IP 和端口，检查网络是否可达",
			"",
			"—— 或者用模拟设备先验证平台是否正常 ——",
			"点击「注册模拟设备」，用虚拟设备验证平台本身没问题，排除是平台的问题",
		)
	} else {
		tips = append(tips, fmt.Sprintf("已有 %d 台设备注册成功，点击设备旁的「体检」按钮开始全链路诊断", len(sessions)))
	}

	result["tips"] = tips
	jsonResponse(w, http.StatusOK, result)
}

// handleQuickStart 一键全自动体检：自动启动平台→注册模拟设备→全链路体检。
// 这是“零配置”入口，用户不需要理解任何概念就能得到一份报告。
func (s *Server) handleQuickStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.hub.BroadcastLog("error", fmt.Sprintf("一键体检内部错误: %v", p))
			}
		}()
		s.hub.BroadcastLog("info", "🚀 一键体检启动，正在自动配置...")
		s.hub.BroadcastStatus("checking", "quickstart")

		// ===== 步骤 1：启动模拟平台（如果未启动）=====
		s.mu.Lock()
		role := s.role
		s.mu.Unlock()

		if role == nil {
			s.hub.BroadcastLog("info", "[1/3] 正在启动模拟上级平台...")
			newRole := sip.NewDeviceSideRole(sip.RoleConfig{
				Host:         "0.0.0.0",
				Port:         5060,
				ServerID:     "34020000002000000001",
				Password:     "12345678",
				ChallengeAlg: "MD5",
			})

			// 注册事件回调
			s.setupRoleCallbacks(newRole)

			if err := newRole.Start(); err != nil {
				// 端口占用则回退
				if strings.Contains(err.Error(), "bind") {
					s.hub.BroadcastLog("warn", "端口 5060 被占用，自动切换到随机端口")
					newRole = sip.NewDeviceSideRole(sip.RoleConfig{
						Host:         "0.0.0.0",
						Port:         0,
						ServerID:     "34020000002000000001",
						Password:     "12345678",
						ChallengeAlg: "MD5",
					})
					s.setupRoleCallbacks(newRole)
					if err2 := newRole.Start(); err2 != nil {
						s.hub.BroadcastError("模拟平台启动失败: " + err2.Error())
						s.hub.BroadcastStatus("idle", nil)
						return
					}
				} else {
					s.hub.BroadcastError("模拟平台启动失败: " + err.Error())
					s.hub.BroadcastStatus("idle", nil)
					return
				}
			}
			s.mu.Lock()
			s.role = newRole
			role = newRole
			s.mu.Unlock()
			port := role.LocalPort()
			s.hub.BroadcastLog("success", fmt.Sprintf("[1/3] 模拟平台已启动，端口 %d", port))
			s.hub.BroadcastStatus("sipsim_started", map[string]int{"port": port})
		} else {
			s.hub.BroadcastLog("info", "[1/3] 模拟平台已在运行中，跳过")
		}

		// ===== 步骤 2：注册模拟设备（如果未注册）=====
		s.mu.Lock()
		var cam *sip.CameraSideRole
		for _, c := range s.cameras {
			cam = c
			break
		}
		s.mu.Unlock()

		deviceID := "34020000001320000001"
		if cam == nil {
			s.hub.BroadcastLog("info", "[2/3] 正在注册模拟设备...")
			port := role.LocalPort()
			serverID := role.ServerID()

			cam = sip.NewCameraSideRole(sip.CameraConfig{
				ServerAddr: "127.0.0.1:" + strconv.Itoa(port),
				ServerID:   serverID,
				DeviceID:   deviceID,
				Password:   "12345678",
				Timeout:    5 * time.Second,
			})

			resp, alg, err := cam.Register()
			if err != nil || resp.StatusCode != 200 {
				cam.Close()
				s.hub.BroadcastError(fmt.Sprintf("[2/3] 模拟设备注册失败: %v", err))
				s.hub.BroadcastStatus("idle", nil)
				return
			}
			cam.StartListener()
			if _, err := cam.Keepalive(1); err != nil {
				s.hub.BroadcastLog("warn", "首次心跳发送失败: "+err.Error())
			}

			s.mu.Lock()
			s.cameras[deviceID] = cam
			s.mu.Unlock()

			// 自动心跳
			go func() {
				sn := 1
				ticker := time.NewTicker(30 * time.Second)
				defer ticker.Stop()
				for range ticker.C {
					sn++
					s.mu.Lock()
					c, ok := s.cameras[deviceID]
					s.mu.Unlock()
					if !ok {
						return
					}
					if _, err := c.Keepalive(sn); err != nil {
						return
					}
				}
			}()

			s.hub.BroadcastLog("success", fmt.Sprintf("[2/3] 模拟设备已注册成功（算法=%s）", alg))
			s.hub.BroadcastStatus("session_update", nil)
		} else {
			s.hub.BroadcastLog("info", "[2/3] 模拟设备已注册，跳过")
		}

		// ===== 步骤 3：全链路体检 =====
		s.hub.BroadcastLog("info", "[3/3] 开始全链路体检...")

		re, _ := rules.NewEngineWithBuiltinRules()
		engine := diag.NewEngine(role, re, diag.CheckConfig{
			DeviceID: deviceID,
		})
		reportData := engine.Run()

		for _, stage := range reportData.Stages {
			s.hub.BroadcastStage(stage)
		}

		s.mu.Lock()
		s.reports[reportData.ReportID] = reportData
		s.mu.Unlock()

		htmlPath := filepath.Join(s.reportDir, reportData.ReportID+".html")
		_ = report.GenerateHTMLFile(reportData, htmlPath)

		s.hub.BroadcastLog("info", fmt.Sprintf("📊 体检完成: 得分 %d/100, 问题 %d 个, 证据 %d 条",
			reportData.Score, len(reportData.AllIssues), reportData.EvidenceCount))
		s.hub.BroadcastDone(reportData.Score, reportData.Passed, reportData.ReportID, len(reportData.AllIssues))
		s.hub.BroadcastStatus("idle", nil)
	}()

	jsonResponse(w, http.StatusAccepted, map[string]string{
		"message": "一键体检已启动",
	})
}

// setupRoleCallbacks 为 DeviceSideRole 注册事件回调。
func (s *Server) setupRoleCallbacks(role *sip.DeviceSideRole) {
	role.OnRegister(func(f sip.RegisterFact) {
		switch f.Kind {
		case "registered":
			s.hub.BroadcastLog("success", fmt.Sprintf("设备 %s 注册成功（算法=%s, Expires=%d）", f.DeviceID, f.Algorithm, f.Expires))
			if f.NATMismatch {
				s.hub.BroadcastLog("warn", fmt.Sprintf("NAT 地址不匹配: Via=%s, 来源=%s", f.ViaAddr, f.ReceivedAddr))
			}
		case "challenge":
			s.hub.BroadcastLog("info", fmt.Sprintf("→ 401 质询 %s", f.DeviceID))
		case "auth_fail":
			s.hub.BroadcastLog("error", fmt.Sprintf("鉴权失败 %s（类别=%s）", f.DeviceID, f.FailureKind))
		case "deregister":
			s.hub.BroadcastLog("info", fmt.Sprintf("设备 %s 注销", f.DeviceID))
		}
		s.hub.BroadcastStatus("session_update", nil)
	})
	role.OnKeepalive(func(f sip.KeepaliveFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("心跳 %s", f.DeviceID))
		s.hub.BroadcastStatus("session_update", nil)
	})
	role.OnCatalog(func(f sip.CatalogFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("目录应答 %s（通道数=%d）", f.DeviceID, len(f.Items)))
	})
	role.OnDeviceInfo(func(f sip.DeviceInfoFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("设备信息 %s（厂商=%s 型号=%s）", f.DeviceID, f.Manufacturer, f.Model))
	})
	role.OnAlarm(func(f sip.AlarmFact) {
		s.hub.BroadcastLog("success", fmt.Sprintf("报警通知 %s（描述=%s）", f.DeviceID, f.Description))
	})
}
