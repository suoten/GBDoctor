package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"gbdoctor/internal/diag"
)

// WSMessage 为 WebSocket 推送消息。
type WSMessage struct {
	Type    string      `json:"type"`    // log | stage | progress | done | error | status
	Time    string      `json:"time"`    // 时间戳
	Stage   string      `json:"stage"`   // 环节名（type=stage 时）
	Payload interface{} `json:"payload"` // 消息内容
}

// Hub 管理所有 WebSocket 连接，支持广播消息。
type Hub struct {
	mu      sync.Mutex
	clients map[*wsClient]bool
}

type wsClient struct {
	conn *websocketConn
	send chan []byte
	hub  *Hub
}

// websocketConn 抽象底层连接（兼容 gorilla/websocket 或 nhooyr/websocket）
// 这里使用最小化接口，实际由 upgrader 创建。
type websocketConn struct {
	w   http.ResponseWriter
	r   *http.Request
	f   http.Flusher
	ch  chan []byte
	end chan struct{}
}

// NewHub 创建 WebSocket 广播中心。
func NewHub() *Hub {
	return &Hub{
		clients: make(map[*wsClient]bool),
	}
}

// Broadcast 向所有连接广播消息。
func (h *Hub) Broadcast(msg WSMessage) {
	data, _ := json.Marshal(msg)
	h.mu.Lock()
	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			// 客户端缓冲满，跳过
		}
	}
	h.mu.Unlock()
}

// BroadcastLog 广播日志消息。
func (h *Hub) BroadcastLog(level, text string) {
	h.Broadcast(WSMessage{
		Type:    "log",
		Time:    time.Now().Format("15:04:05"),
		Payload: map[string]string{"level": level, "text": text},
	})
}

// BroadcastStage 广播环节完成消息。
func (h *Hub) BroadcastStage(stage diag.StageResult) {
	status := "skipped"
	if !stage.Skipped && stage.Passed {
		status = "pass"
	} else if !stage.Skipped && !stage.Passed {
		status = "fail"
	}
	h.Broadcast(WSMessage{
		Type:  "stage",
		Time:  time.Now().Format("15:04:05"),
		Stage: string(stage.Stage),
		Payload: map[string]interface{}{
			"status":   status,
			"stage":    string(stage.Stage),
			"facts":    stage.Facts,
			"duration": diag.FormatDuration(stage.Duration),
			"issues":   stage.Issues,
		},
	})
}

// BroadcastDone 广播体检完成消息。
func (h *Hub) BroadcastDone(score int, passed bool, reportID string, issueCount int) {
	h.Broadcast(WSMessage{
		Type: "done",
		Time: time.Now().Format("15:04:05"),
		Payload: map[string]interface{}{
			"score":     score,
			"passed":    passed,
			"report_id": reportID,
			"issues":    issueCount,
		},
	})
}

// BroadcastStatus 广播状态变更。
func (h *Hub) BroadcastStatus(status string, detail interface{}) {
	h.Broadcast(WSMessage{
		Type:    "status",
		Time:    time.Now().Format("15:04:05"),
		Payload: map[string]interface{}{"status": status, "detail": detail},
	})
}

// BroadcastError 广播错误消息。
func (h *Hub) BroadcastError(text string) {
	h.Broadcast(WSMessage{
		Type:    "error",
		Time:    time.Now().Format("15:04:05"),
		Payload: map[string]string{"text": text},
	})
}

// register 注册客户端。
func (h *Hub) register(client *wsClient) {
	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()
}

// unregister 注销客户端。
func (h *Hub) unregister(client *wsClient) {
	h.mu.Lock()
	delete(h.clients, client)
	h.mu.Unlock()
	close(client.send)
}

// ServeWS 处理 WebSocket 升级请求。
// 使用原生 HTTP 实现，不依赖第三方库。
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return
	}

	// 执行 WebSocket 握手（原生实现）
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket requires hijackable connection", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// 发送握手响应
	acceptKey := computeAcceptKey(key)
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	rw.WriteString("Upgrade: websocket\r\n")
	rw.WriteString("Connection: Upgrade\r\n")
	rw.WriteString("Sec-WebSocket-Accept: " + acceptKey + "\r\n")
	rw.WriteString("\r\n")
	rw.Flush()

	client := &wsClient{
		conn: &websocketConn{ch: make(chan []byte, 256), end: make(chan struct{})},
		send: make(chan []byte, 256),
		hub:  h,
	}
	h.register(client)
	defer h.unregister(client)

	// 读取循环（忽略客户端消息）
	go func() {
		buf := make([]byte, 512)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				close(client.conn.end)
				return
			}
		}
	}()

	// 写入循环
	for {
		select {
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			if err := writeWSFrame(conn, msg); err != nil {
				return
			}
		case <-client.conn.end:
			return
		}
	}
}
