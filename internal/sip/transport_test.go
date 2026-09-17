package sip

import (
	"strconv"
	"testing"
	"time"
)

func TestUDPLoopback(t *testing.T) {
	rx := NewUDPTransport("127.0.0.1", 0, 16)
	if err := rx.Start(); err != nil {
		t.Fatalf("UDP 监听失败: %v", err)
	}
	defer rx.Close()

	tx := NewUDPTransport("127.0.0.1", 0, 16)
	if err := tx.Start(); err != nil {
		t.Fatalf("UDP 监听失败: %v", err)
	}
	defer tx.Close()

	addr := "127.0.0.1:" + strconv.Itoa(rx.LocalPort())
	payload := []byte("REGISTER sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	if err := tx.Send(payload, addr); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	select {
	case pkt := <-rx.Packets():
		if string(pkt.Raw) != string(payload) {
			t.Errorf("回环内容不符: %q", pkt.Raw)
		}
		if pkt.Proto != "udp" || pkt.Src == "" {
			t.Errorf("Packet 元数据错误: %+v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("2s 内未收到回环报文")
	}
}

func TestTCPFraming(t *testing.T) {
	rx := NewTCPTransport("127.0.0.1", 0, 16)
	if err := rx.Start(); err != nil {
		t.Fatalf("TCP 监听失败: %v", err)
	}
	defer rx.Close()

	body := "<Notify><CmdType>Keepalive</CmdType><SN>1</SN></Notify>"
	msg := "MESSAGE sip:x SIP/2.0\r\nContent-Type: Application/MANSCDP+xml\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	// 粘包：两条消息一次写入
	payload := []byte(msg + msg)

	conn, err := dialForTest("127.0.0.1", rx.LocalPort())
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	for i := 0; i < 2; i++ {
		select {
		case pkt := <-rx.Packets():
			if string(pkt.Raw) != msg {
				t.Fatalf("TCP 第 %d 条报文定界错误: %q", i+1, pkt.Raw)
			}
			m := Parse(pkt.Raw)
			if m.BodyText() != body {
				t.Errorf("body 解析错误: %q", m.BodyText())
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("2s 内未收到 TCP 报文 %d", i+1)
		}
	}
}
