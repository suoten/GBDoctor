package sip

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// dialForTest 建立到 TCP 传输的原始连接（供粘包测试写入）。
func dialForTest(host string, port int) (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
}

func newTestRole(t *testing.T) (*DeviceSideRole, int) {
	t.Helper()
	role := NewDeviceSideRole(RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001", Password: "12345678",
	})
	if err := role.Start(); err != nil {
		t.Fatalf("模拟平台启动失败: %v", err)
	}
	t.Cleanup(role.Cleanup)
	return role, role.LocalPort()
}

func sendRawUDP(host string, port int, raw []byte) error {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(raw)
	return err
}

func newCam(port int, password string) *CameraSideRole {
	return NewCameraSideRole(CameraConfig{
		ServerAddr: "127.0.0.1:" + strconv.Itoa(port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   password,
		Timeout:    3 * time.Second,
	})
}

// TestRegisterAndKeepalive E2E：simcam 注册 → 401 → 鉴权 → 200 → 心跳 200。
func TestRegisterAndKeepalive(t *testing.T) {
	role, port := newTestRole(t)

	regCh := make(chan RegisterFact, 8)
	kaCh := make(chan KeepaliveFact, 8)
	role.OnRegister(func(f RegisterFact) { regCh <- f })
	role.OnKeepalive(func(f KeepaliveFact) { kaCh <- f })

	cam := newCam(port, "12345678")
	defer cam.Close()

	resp, alg, err := cam.Register()
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("注册应 200 OK，实际 %d", resp.StatusCode)
	}
	if alg == "" {
		t.Errorf("应返回鉴权算法")
	}

	sess, ok := role.Session("34020000001320000001")
	if !ok {
		t.Fatalf("注册成功后会话应存在")
	}
	if sess.Expires != 3600 || sess.RegisterCount != 1 {
		t.Errorf("会话字段错误: %+v", sess)
	}
	if !sess.LastKeepaliveAt.IsZero() {
		t.Errorf("注册后不应有心跳时间")
	}

	if resp, err := cam.Keepalive(1); err != nil || resp.StatusCode != 200 {
		t.Fatalf("心跳失败: resp=%v err=%v", resp, err)
	}

	select {
	case f := <-regCh:
		// 首个 REGISTER 会先产出 challenge 事实，排空直到 registered
		for f.Kind == "challenge" {
			select {
			case f = <-regCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("未收到 registered 事实")
			}
		}
		if f.Kind != "registered" || !f.DeviceIDValid {
			t.Fatalf("注册事实错误: %+v", f)
		}
		if f.NATMismatch {
			t.Errorf("回环地址不应判定 NAT 不一致")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("未收到注册事实")
	}
	select {
	case f := <-kaCh:
		if !f.OK || f.DeviceID != "34020000001320000001" {
			t.Errorf("心跳事实错误: %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("未收到心跳事实")
	}

	if s, _ := role.Session("34020000001320000001"); s.KeepaliveCount != 1 {
		t.Errorf("心跳计数 = %d, want 1", s.KeepaliveCount)
	}
}

// TestRegisterWrongPassword 鉴权失败路径：密码错误持续 401 并产出 auth_fail。
func TestRegisterWrongPassword(t *testing.T) {
	role, port := newTestRole(t)

	failCh := make(chan RegisterFact, 8)
	role.OnRegister(func(f RegisterFact) {
		if f.Kind == "auth_fail" {
			failCh <- f
		}
	})

	cam := newCam(port, "wrong-pass")
	defer cam.Close()

	resp, err := cam.sendRegister("")
	if err != nil {
		t.Fatalf("首次注册请求失败: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("首次注册应 401，实际 %d", resp.StatusCode)
	}
	resp, err = cam.sendRegister(resp.Headers.Get("www-authenticate"))
	if err != nil {
		t.Fatalf("鉴权请求失败: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("密码错误应 401，实际 %d", resp.StatusCode)
	}

	select {
	case f := <-failCh:
		if f.FailureKind != "mismatch" {
			t.Errorf("失败类别 = %q, want mismatch", f.FailureKind)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("未收到 auth_fail 事实")
	}
	if v := role.auth.FailureCount("34020000001320000001"); v != 1 {
		t.Errorf("失败计数 = %d, want 1", v)
	}
}
