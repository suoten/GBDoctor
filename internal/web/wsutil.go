package web

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net"
)

// computeAcceptKey 计算 WebSocket 握手响应 key。
// RFC 6455: 将 Sec-WebSocket-Key 与 magic string 拼接后 SHA-1，再 base64 编码。
func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// writeWSFrame 写入一个 WebSocket 文本帧（服务端→客户端，不掩码）。
// RFC 6455 Section 5.5.6: 服务端发送的帧不需要掩码。
func writeWSFrame(conn net.Conn, data []byte) error {
	// 帧头：FIN=1, opcode=1(text)
	header := []byte{0x81}

	length := len(data)
	switch {
	case length < 126:
		header = append(header, byte(length))
	case length < 65536:
		header = append(header, 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		header = append(header, ext...)
	default:
		header = append(header, 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		header = append(header, ext...)
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}
