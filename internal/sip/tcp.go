package sip

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TCPTransport 基于 TCP 的传输（按 Content-Length 定界拆包）。
type TCPTransport struct {
	host     string
	port     int
	ch       chan Packet
	listener net.Listener
	conns    map[string]net.Conn
	mu       sync.Mutex
	closed   bool
}

// NewTCPTransport 创建 TCP 传输（port=0 自动分配）。
func NewTCPTransport(host string, port int, buf int) *TCPTransport {
	if buf <= 0 {
		buf = 1024
	}
	return &TCPTransport{host: host, port: port, ch: make(chan Packet, buf), conns: map[string]net.Conn{}}
}

// Start 监听并启动接收循环。
func (t *TCPTransport) Start() error {
	addr := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = ln
	go t.acceptLoop()
	return nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		key := conn.RemoteAddr().String()
		t.mu.Lock()
		t.conns[key] = conn
		t.mu.Unlock()
		go t.readLoop(conn, key)
	}
}

func (t *TCPTransport) readLoop(conn net.Conn, key string) {
	defer func() {
		t.mu.Lock()
		delete(t.conns, key)
		t.mu.Unlock()
		_ = conn.Close()
	}()
	br := bufio.NewReader(conn)
	for {
		raw, err := readSIPMessage(br)
		if err != nil {
			return
		}
		select {
		case t.ch <- Packet{Raw: raw, Src: key, Proto: "tcp", TS: time.Now()}:
		default:
		}
	}
}

// readSIPMessage 按 Content-Length 从流中读取一条完整 SIP 报文。
func readSIPMessage(br *bufio.Reader) ([]byte, error) {
	head, err := readUntilDoubleCRLF(br)
	if err != nil {
		return nil, err
	}
	cl := parseContentLength(string(head))
	if cl <= 0 {
		return head, nil
	}
	body := make([]byte, cl)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

func readUntilDoubleCRLF(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		out = append(out, line...)
		if line == "\r\n" || line == "\n" {
			// 空行 = 头部结束；保留完整分隔符以还原原始字节
			return out, nil
		}
		if len(out) > 1<<20 {
			return nil, errors.New("sip tcp 头部超长")
		}
	}
}

func parseContentLength(head string) int {
	for _, ln := range strings.Split(head, "\n") {
		i := strings.Index(ln, ":")
		if i <= 0 {
			continue
		}
		if normHeaderName(ln[:i]) == "content-length" {
			n, _ := strconv.Atoi(strings.TrimSpace(ln[i+1:]))
			return n
		}
	}
	return 0
}

// Send 经已有连接或新建连接发送报文。
func (t *TCPTransport) Send(raw []byte, addr string) error {
	t.mu.Lock()
	conn := t.conns[addr]
	t.mu.Unlock()
	if conn != nil {
		if _, err := conn.Write(raw); err == nil {
			return nil
		}
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.conns[addr] = c
	t.mu.Unlock()
	go t.readLoop(c, addr)
	_, err = c.Write(raw)
	return err
}

// Packets 返回接收通道。
func (t *TCPTransport) Packets() <-chan Packet { return t.ch }

// Protocol 返回传输协议名。
func (t *TCPTransport) Protocol() string { return "tcp" }

// LocalPort 返回实际监听端口。
func (t *TCPTransport) LocalPort() int {
	if t.listener != nil {
		if addr, ok := t.listener.Addr().(*net.TCPAddr); ok {
			return addr.Port
		}
	}
	return t.port
}

// Close 关闭监听与全部连接。
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.listener != nil {
		_ = t.listener.Close()
	}
	for _, c := range t.conns {
		_ = c.Close()
	}
	t.conns = map[string]net.Conn{}
	return nil
}
