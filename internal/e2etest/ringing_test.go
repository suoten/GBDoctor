// Package e2etest — 回归测试：真实摄像头常见行为（先回 100/180 临时响应）。
//
// 回归目标（2026-09 修复的 P0 缺陷）：
//  1. SendInvite 曾把第一个响应（100 Trying）当最终应答，导致好摄像头
//     被系统性误报 "INVITE 被拒绝（100）"；修复后必须跳过 1xx 等待最终应答。
//  2. 应答通道曾在发送报文之后才注册，亚毫秒级往返中响应被丢弃导致超时误报；
//     修复后先注册通道再发送。
//  3. 点播结束后必须发送 BYE 挂断，否则设备持续推流，重复体检被 486 拒绝产生假故障。
package e2etest

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gbdoctor/internal/sip"
)

// fakeRingingDevice 一台"先回 100 Trying 再回 200 OK"的裸 UDP 假设备。
type fakeRingingDevice struct {
	conn     *net.UDPConn
	deviceID string
	serverID string
	password string
}

func newFakeRingingDevice(t *testing.T, serverAddr, deviceID, serverID, password string) *fakeRingingDevice {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("解析平台地址失败: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("假设备 UDP 建连失败: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return &fakeRingingDevice{conn: conn, deviceID: deviceID, serverID: serverID, password: password}
}

func (d *fakeRingingDevice) send(t *testing.T, raw string) {
	t.Helper()
	if _, err := d.conn.Write([]byte(raw)); err != nil {
		t.Errorf("假设备发送失败: %v", err)
	}
}

func (d *fakeRingingDevice) recv(t *testing.T) *sip.SipMessage {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := d.conn.Read(buf)
	if err != nil {
		t.Errorf("假设备接收超时/失败: %v", err)
		return nil
	}
	return sip.Parse(buf[:n])
}

// register 完成 401 质询 → 鉴权注册 → 200 OK 流程。
func (d *fakeRingingDevice) register(t *testing.T) {
	t.Helper()
	callID := fmt.Sprintf("reg-%d", time.Now().UnixNano())

	// 第一遍：无鉴权 REGISTER，期待 401
	reg1 := fmt.Sprintf("REGISTER sip:%s@%s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:59999;branch=z9hG4bKfake1\r\n"+
		"From: <sip:%s@%s>;tag=faketag1\r\n"+
		"To: <sip:%s@%s>\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: 1 REGISTER\r\n"+
		"Contact: <sip:%s@127.0.0.1:59999>\r\n"+
		"Max-Forwards: 70\r\n"+
		"Expires: 3600\r\n"+
		"Content-Length: 0\r\n\r\n",
		d.deviceID, d.serverID, d.deviceID, d.serverID, d.deviceID, d.serverID, callID, d.deviceID)
	d.send(t, reg1)
	resp401 := d.recv(t)
	if resp401.StatusCode != 401 {
		t.Fatalf("期待 401 质询，实际: %d", resp401.StatusCode)
	}
	www := resp401.Headers.Get("www-authenticate")
	p := sip.ParseAuthParams(www)
	if p["nonce"] == "" {
		t.Fatalf("401 缺少 nonce: %q", www)
	}
	realm := p["realm"]
	uri := fmt.Sprintf("sip:%s@%s", d.deviceID, d.serverID)
	response := sip.ComputeDigestResponse(d.deviceID, realm, d.password, "REGISTER", uri, p["nonce"], "", "", "", "MD5")

	// 第二遍：带鉴权 REGISTER，期待 200
	reg2 := fmt.Sprintf("REGISTER %s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:59999;branch=z9hG4bKfake2\r\n"+
		"From: <sip:%s@%s>;tag=faketag1\r\n"+
		"To: <sip:%s@%s>\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: 2 REGISTER\r\n"+
		"Contact: <sip:%s@127.0.0.1:59999>\r\n"+
		"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=MD5\r\n"+
		"Max-Forwards: 70\r\n"+
		"Expires: 3600\r\n"+
		"Content-Length: 0\r\n\r\n",
		uri, d.deviceID, d.serverID, d.deviceID, d.serverID, callID, d.deviceID,
		d.deviceID, realm, p["nonce"], uri, response)
	d.send(t, reg2)
	resp200 := d.recv(t)
	if resp200.StatusCode != 200 {
		t.Fatalf("注册失败: %d %s", resp200.StatusCode, resp200.ReasonPhrase)
	}
}

// answerInviteWithRinging 模拟设备先回 100 Trying、再回 200 OK(SDP)。
func (d *fakeRingingDevice) answerInviteWithRinging(t *testing.T) {
	t.Helper()
	inv := d.recv(t)
	if inv == nil {
		return
	}
	if inv.Method != "INVITE" {
		t.Errorf("期待 INVITE，实际: %v", inv.Method)
		return
	}
	// 先回 100 Trying（旧代码会把它当最终应答 → 误报）
	trying := sip.CreateResponse(inv, 100, "")
	d.send(t, string(trying.Bytes()))
	time.Sleep(150 * time.Millisecond)
	// 再回 200 OK + SDP
	ok := sip.CreateResponse(inv, 200, "")
	ok.Headers.Set("Content-Type", "application/sdp")
	sdp := "v=0\r\n" +
		fmt.Sprintf("o=%s 0 0 IN IP4 127.0.0.1\r\n", d.deviceID) +
		"s=Play\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=video 30000 RTP/AVP 96\r\n" +
		"a=rtpmap:96 PS/90000\r\n" +
		"a=sendrecv\r\n" +
		"y=0100000001\r\n"
	ok.Body = []byte(sdp)
	d.send(t, string(ok.Bytes()))
	// 等待平台 ACK（不严格校验）
	_ = d.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	if n, err := d.conn.Read(buf); err == nil {
		if !strings.HasPrefix(string(buf[:n]), "ACK") {
			t.Logf("提示：ACK 后收到其他报文: %.20s", buf[:n])
		}
	}
	_ = d.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
}

// waitRequest 等待指定方法的请求。
func (d *fakeRingingDevice) waitRequest(t *testing.T, method string, timeout time.Duration) *sip.SipMessage {
	t.Helper()
	_ = d.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = d.conn.SetReadDeadline(time.Now().Add(5 * time.Second)) }()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		buf := make([]byte, 65535)
		n, err := d.conn.Read(buf)
		if err != nil {
			break
		}
		msg := sip.Parse(buf[:n])
		if msg.IsRequest && msg.Method == method {
			return msg
		}
	}
	return nil
}

// TestSendInviteSkipsRinging 验证 SendInvite 跳过 100/180 临时响应并拿到 200 OK。
func TestSendInviteSkipsRinging(t *testing.T) {
	serverID := "34020000002000000001"
	deviceID := "34020000001320000001"

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host:         "127.0.0.1",
		Port:         0,
		ServerID:     serverID,
		Password:     "ringtest",
		ChallengeAlg: "MD5",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	defer role.Cleanup()

	dev := newFakeRingingDevice(t, fmt.Sprintf("127.0.0.1:%d", role.LocalPort()), deviceID, serverID, "ringtest")
	defer dev.conn.Close()

	dev.register(t)
	// 等会话就绪
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := role.Session(deviceID); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := role.Session(deviceID); !ok {
		t.Fatal("设备会话未建立")
	}

	// 设备侧：先回 100 再回 200
	go dev.answerInviteWithRinging(t)

	resp, err := role.SendInvite(deviceID, deviceID, 30000, "0100000001")
	if err != nil {
		t.Fatalf("SendInvite 失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("【回归失败】SendInvite 应跳过 1xx 拿到 200 OK，实际: %d %s", resp.StatusCode, resp.ReasonPhrase)
	}
	if len(resp.Body) == 0 || !strings.Contains(resp.BodyText(), "m=video") {
		t.Fatal("【回归失败】200 OK 应携带 SDP 媒体行")
	}
	t.Log("✅ SendInvite 正确跳过 100 Trying，拿到 200 OK（含 SDP）")

	// 验证 BYE：点播结束后平台应发送 BYE 挂断
	go func() {
		// 设备侧先对 200 OK 的会话不再推流，直接等 BYE
		bye := dev.waitRequest(t, "BYE", 3*time.Second)
		if bye == nil {
			t.Error("【回归失败】点播结束后未收到 BYE，设备将持续推流")
			return
		}
		// 回 200 OK 结束事务
		okResp := sip.CreateResponse(bye, 200, "")
		_, _ = dev.conn.Write([]byte(okResp.Bytes()))
	}()
	if err := role.SendBye(deviceID, deviceID); err != nil {
		t.Fatalf("SendBye 失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	t.Log("✅ BYE 已发送且设备收到（回归通过）")
}
