package sip

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CameraConfig 为模拟摄像头配置。
type CameraConfig struct {
	ServerAddr string // 平台地址 "host:port"
	ServerID   string // 平台编码
	DeviceID   string // 设备编码（用户名）
	Password   string
	Transport  string        // udp / tcp，默认 udp
	LocalPort  int           // 本地监听端口，0 自动分配
	Expires    int           // 注册有效期，默认 3600
	Timeout    time.Duration // 单次请求超时，默认 5s
}

// CameraSideRole 模拟摄像头（SIP 客户端）：注册/保活/查询。
// 平台侧体检（M4）与 simcam 自检共用本角色。
type CameraSideRole struct {
	cfg      CameraConfig
	conn     clientConn
	cseq     int
	lastAuth string
	lastSent *SipMessage
	mu       sync.Mutex
	closed   bool

	// 入站监听器（V1.2：处理平台发来的 MESSAGE/INVITE）
	listener *CameraListener

	// 响应分发 channel（listenLoop 读到响应报文后通过此 channel 转发给 awaitResponse）
	respCh chan *SipMessage
}

// clientConn 为客户端连接抽象（UDP/TCP 统一）。
type clientConn interface {
	WriteRaw(raw []byte) error
	ReadMsg(timeout time.Duration) (*SipMessage, error)
	LocalAddr() string
	Close() error
}

// udpClientConn 基于 net.UDPConn。
type udpClientConn struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
	local  string
}

func (c *udpClientConn) WriteRaw(raw []byte) error {
	_, err := c.conn.WriteToUDP(raw, c.remote)
	return err
}

func (c *udpClientConn) ReadMsg(timeout time.Duration) (*SipMessage, error) {
	buf := make([]byte, 65535)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		msg := Parse(raw)
		if msg.StatusCode > 0 || msg.IsRequest {
			return msg, nil
		}
	}
}

func (c *udpClientConn) LocalAddr() string { return c.local }

func (c *udpClientConn) Close() error { return c.conn.Close() }

// tcpClientConn 基于 net.Conn + Content-Length 定界。
type tcpClientConn struct {
	conn  net.Conn
	br    *bufio.Reader
	local string
}

func (c *tcpClientConn) WriteRaw(raw []byte) error {
	_, err := c.conn.Write(raw)
	return err
}

func (c *tcpClientConn) ReadMsg(timeout time.Duration) (*SipMessage, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	raw, err := readSIPMessage(c.br)
	if err != nil {
		return nil, err
	}
	return Parse(raw), nil
}

func (c *tcpClientConn) LocalAddr() string { return c.local }

func (c *tcpClientConn) Close() error { return c.conn.Close() }

// NewCameraSideRole 创建模拟摄像头。
func NewCameraSideRole(cfg CameraConfig) *CameraSideRole {
	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	if cfg.Expires == 0 {
		cfg.Expires = 3600
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &CameraSideRole{cfg: cfg, cseq: 1}
}

// Connect 建立传输连接。
func (c *CameraSideRole) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	if strings.EqualFold(c.cfg.Transport, "tcp") {
		conn, err := net.DialTimeout("tcp", c.cfg.ServerAddr, c.cfg.Timeout)
		if err != nil {
			return err
		}
		c.conn = &tcpClientConn{conn: conn, br: bufio.NewReader(conn), local: conn.LocalAddr().String()}
		return nil
	}
	raddr, err := net.ResolveUDPAddr("udp", c.cfg.ServerAddr)
	if err != nil {
		return err
	}
	var laddr *net.UDPAddr
	if c.cfg.LocalPort > 0 {
		laddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(c.cfg.LocalPort)))
		if err != nil {
			return err
		}
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	local := conn.LocalAddr().String()
	if c.cfg.LocalPort > 0 {
		local = net.JoinHostPort(OutboundIP(c.cfg.ServerAddr), strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))
	}
	c.conn = &udpClientConn{conn: conn, remote: raddr, local: local}
	return nil
}

// Close 关闭连接（幂等）。
func (c *CameraSideRole) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener != nil {
		c.listener.Stop()
	}
	if c.closed {
		return nil
	}
	c.closed = true
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// StartListener 启动入站请求监听器（V1.2）。
// 使模拟摄像头能够处理平台发来的 MESSAGE（Catalog/DeviceInfo 查询）
// 和 INVITE（点播请求），自动应答并发送模拟 RTP 流。
// 启动后 listenLoop 成为唯一的读取者，响应报文通过 respCh 转发给 awaitResponse。
func (c *CameraSideRole) StartListener() *CameraListener {
	c.mu.Lock()
	if c.listener != nil {
		c.mu.Unlock()
		return c.listener
	}
	c.respCh = make(chan *SipMessage, 16)
	c.listener = NewCameraListener(c)
	c.mu.Unlock()
	_ = c.listener.Start()
	return c.listener
}

// Listener 返回已创建的监听器（可能为 nil）。
func (c *CameraSideRole) Listener() *CameraListener {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listener
}

// nextCSeq 生成下一个 CSeq 序号。
func (c *CameraSideRole) nextCSeq() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cseq++
	return c.cseq
}

func randToken(n int) string {
	var buf [16]byte
	_, _ = rand.Read(buf[:n])
	return hex.EncodeToString(buf[:n])[:n]
}
