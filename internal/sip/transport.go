package sip

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Packet 是传输层收到的原始报文（证据链最小单元）。
type Packet struct {
	Raw   []byte
	Src   string    // 对端 "ip:port"
	Proto string    // udp / tcp
	TS    time.Time // 到达时刻
}

// Transport 为 UDP/TCP 统一传输接口。
type Transport interface {
	Start() error
	Close() error
	Send(raw []byte, addr string) error
	Packets() <-chan Packet
	Protocol() string
	LocalPort() int
}

// UDPTransport 基于 UDP 的传输（国标默认形态）。
type UDPTransport struct {
	host   string
	port   int
	ch     chan Packet
	conn   *net.UDPConn
	mu     sync.Mutex
	closed bool
}

// NewUDPTransport 创建 UDP 传输（port=0 自动分配）。
func NewUDPTransport(host string, port int, buf int) *UDPTransport {
	if buf <= 0 {
		buf = 1024
	}
	return &UDPTransport{host: host, port: port, ch: make(chan Packet, buf)}
}

// Start 监听并启动接收循环。
func (u *UDPTransport) Start() error {
	addr := net.JoinHostPort(u.host, strconv.Itoa(u.port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	u.conn = conn
	go u.readLoop()
	return nil
}

func (u *UDPTransport) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, src, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			u.mu.Lock()
			closed := u.closed
			u.mu.Unlock()
			if closed {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		pkt := Packet{Raw: raw, Src: src.String(), Proto: "udp", TS: time.Now()}
		select {
		case u.ch <- pkt:
		default:
			// 缓冲满：丢弃最旧事件，宁可丢包也不阻塞收发
			select {
			case <-u.ch:
			default:
			}
			select {
			case u.ch <- pkt:
			default:
			}
		}
	}
}

// Send 向指定地址发送原始报文。
func (u *UDPTransport) Send(raw []byte, addr string) error {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == nil {
		return errors.New("udp transport 未启动")
	}
	_, err = u.conn.WriteToUDP(raw, raddr)
	return err
}

// Packets 返回接收通道。
func (u *UDPTransport) Packets() <-chan Packet { return u.ch }

// Protocol 返回传输协议名。
func (u *UDPTransport) Protocol() string { return "udp" }

// LocalPort 返回实际监听端口。
func (u *UDPTransport) LocalPort() int {
	if u.conn != nil {
		if addr, ok := u.conn.LocalAddr().(*net.UDPAddr); ok {
			return addr.Port
		}
	}
	return u.port
}

// Close 关闭监听。
func (u *UDPTransport) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// OutboundIP 探测到 target 可达的本机出口 IP（UDP connect 不实际发包）。
// 任何探测失败都回落 127.0.0.1，绝不抛出（移植自 roles._outbound_ip）。
func OutboundIP(target string) string {
	host := defaultHost(target)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "9"), time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		ip := addr.IP.String()
		if ip != "" && ip != "<nil>" {
			return ip
		}
	}
	return "127.0.0.1"
}

func defaultHost(target string) string {
	if i := strings.LastIndex(target, ":"); i > 0 {
		target = target[:i]
	}
	if target == "" {
		target = "127.0.0.1"
	}
	return strings.Trim(target, "[]")
}
