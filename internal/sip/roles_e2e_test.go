package sip

import (
	"strings"
	"testing"
	"time"
)

// TestRegisterSM3Challenge 挑战算法探测：SM3 质询下设备仍可完成注册。
func TestRegisterSM3Challenge(t *testing.T) {
	role := NewDeviceSideRole(RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001", Password: "12345678",
		ChallengeAlg: AlgoSM3,
	})
	if err := role.Start(); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(role.Cleanup)
	port := role.LocalPort()

	cam := newCam(port, "12345678")
	defer cam.Close()

	resp, alg, err := cam.Register()
	if err != nil {
		t.Fatalf("SM3 注册失败: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("SM3 注册应 200，实际 %d", resp.StatusCode)
	}
	if alg != AlgoSM3 {
		t.Errorf("算法应 SM3，实际 %q", alg)
	}
	if s, _ := role.Session("34020000001320000001"); s.Algorithm != AlgoSM3 {
		t.Errorf("会话算法 = %q, want SM3", s.Algorithm)
	}
}

// TestNATMismatch 伪造 Via sent-by 与实际来源不一致 → NAT 事实。
func TestNATMismatch(t *testing.T) {
	role, port := newTestRole(t)

	regCh := make(chan RegisterFact, 8)
	role.OnRegister(func(f RegisterFact) {
		if f.Kind == "challenge" {
			regCh <- f
		}
	})

	raw := "REGISTER sip:34020000002000000001 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.255.255.1:60000;rport;branch=z9hG4bKnat\r\n" +
		"From: <sip:34020000001320000001@34020000002000000001>;tag=nat\r\n" +
		"To: <sip:34020000001320000001@34020000002000000001>\r\n" +
		"Call-ID: nat-1\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n" +
		"Contact: <sip:34020000001320000001@10.255.255.1:60000>\r\nExpires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"

	if err := sendRawUDP("127.0.0.1", port, []byte(raw)); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	select {
	case f := <-regCh:
		if !f.NATMismatch {
			t.Errorf("Via(10.255.255.1:60000) vs 来源(%s) 应判定 NAT 不一致", f.ReceivedAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("未收到质询事实")
	}
}

// TestDeregister Expires=0 注销删除会话。
func TestDeregister(t *testing.T) {
	role, port := newTestRole(t)

	cam := newCam(port, "12345678")
	defer cam.Close()

	if resp, _, err := cam.Register(); err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %v", resp, err)
	}
	cam.cfg.Expires = 0
	if resp, _, err := cam.Register(); err != nil || resp.StatusCode != 200 {
		t.Fatalf("注销失败: %v %v", resp, err)
	}
	if _, ok := role.Session("34020000001320000001"); ok {
		t.Errorf("注销后会话应删除")
	}
}

// TestEvidenceRedactionInRole 平台证据链：入站 REGISTER 的 Authorization 被脱敏。
func TestEvidenceRedactionInRole(t *testing.T) {
	role, port := newTestRole(t)

	cam := newCam(port, "12345678")
	defer cam.Close()
	if _, _, err := cam.Register(); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	evs := role.Evidence().All()
	if len(evs) == 0 {
		t.Fatalf("应有证据记录")
	}
	sawIn := false
	for _, ev := range evs {
		if ev.Direction == "in" {
			sawIn = true
			if ev.RawSHA256 == "" || ev.Size == 0 {
				t.Errorf("入站证据缺少指纹/长度: %+v", ev)
			}
		}
		if strings.Contains(ev.RawText, "response=") {
			t.Errorf("证据中 Authorization 未脱敏: %q", ev.RawText)
		}
	}
	if !sawIn {
		t.Errorf("应有入站证据")
	}
}
