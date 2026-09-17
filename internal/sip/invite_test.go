package sip

import (
	"testing"
)

func TestParseSDP(t *testing.T) {
	body := "v=0\r\n" +
		"o=34020000001320000001 0 0 IN IP4 192.168.1.100\r\n" +
		"s=Play\r\n" +
		"c=IN IP4 192.168.1.100\r\n" +
		"t=0 0\r\n" +
		"m=video 6000 RTP/AVP 96\r\n" +
		"a=rtpmap:96 PS/90000\r\n" +
		"y=0100000001\r\n"

	sdp := ParseSDP(body)
	if sdp == nil {
		t.Fatal("ParseSDP 返回 nil")
	}
	if sdp.SessionName != "Play" {
		t.Errorf("SessionName = %q, want Play", sdp.SessionName)
	}
	if sdp.IPAddress != "192.168.1.100" {
		t.Errorf("IPAddress = %q, want 192.168.1.100", sdp.IPAddress)
	}
	if sdp.MediaType != "video" {
		t.Errorf("MediaType = %q, want video", sdp.MediaType)
	}
	if sdp.Port != 6000 {
		t.Errorf("Port = %d, want 6000", sdp.Port)
	}
	if sdp.Transport != "RTP/AVP" {
		t.Errorf("Transport = %q, want RTP/AVP", sdp.Transport)
	}
	if sdp.SSRC != "0100000001" {
		t.Errorf("SSRC = %q, want 0100000001", sdp.SSRC)
	}
}

func TestSDPValidations(t *testing.T) {
	// 完整 SDP
	good := &SDPInfo{
		SessionName: "Play",
		IPAddress:   "203.0.113.1",
		Port:        6000,
		SSRC:        "0100000001",
	}
	if devs := SDPValidations(good); len(devs) != 0 {
		t.Errorf("合法 SDP 不应有偏差: %v", devs)
	}

	// 缺少 SSRC
	noSSRC := &SDPInfo{
		SessionName: "Play",
		IPAddress:   "203.0.113.1",
		Port:        6000,
	}
	devs := SDPValidations(noSSRC)
	if len(devs) == 0 {
		t.Errorf("缺少 SSRC 应有偏差")
	}

	// SSRC 长度不对
	badSSRC := &SDPInfo{
		SessionName: "Play",
		IPAddress:   "203.0.113.1",
		Port:        6000,
		SSRC:        "123",
	}
	devs = SDPValidations(badSSRC)
	if len(devs) == 0 {
		t.Errorf("SSRC 长度不对应有偏差")
	}

	// 端口为 0
	portZero := &SDPInfo{
		SessionName: "Play",
		IPAddress:   "203.0.113.1",
		Port:        0,
		SSRC:        "0100000001",
	}
	devs = SDPValidations(portZero)
	if len(devs) == 0 {
		t.Errorf("端口为 0 应有偏差")
	}

	// 私网 IP
	privateIP := &SDPInfo{
		SessionName: "Play",
		IPAddress:   "192.168.1.100",
		Port:        6000,
		SSRC:        "0100000001",
	}
	devs = SDPValidations(privateIP)
	if len(devs) == 0 {
		t.Errorf("私网 IP 应有偏差")
	}
}

func TestSSRCFromYField(t *testing.T) {
	if s := SSRCFromYField("0100000001"); s != "0100000001" {
		t.Errorf("SSRC = %q, want 0100000001", s)
	}
	if s := SSRCFromYField("abc"); s != "" {
		t.Errorf("非法 SSRC 应返回空串: %q", s)
	}
	if s := SSRCFromYField("0100000001a"); s != "" {
		t.Errorf("超长 SSRC 应返回空串: %q", s)
	}
}

func TestIsPrivateIP(t *testing.T) {
	if !isPrivateIP("192.168.1.1") {
		t.Errorf("192.168.1.1 应为私网")
	}
	if !isPrivateIP("10.0.0.1") {
		t.Errorf("10.0.0.1 应为私网")
	}
	if !isPrivateIP("172.16.0.1") {
		t.Errorf("172.16.0.1 应为私网")
	}
	if !isPrivateIP("100.64.0.1") {
		t.Errorf("100.64.0.1 应为运营商级 NAT")
	}
	if isPrivateIP("203.0.113.1") {
		t.Errorf("203.0.113.1 不应为私网")
	}
}
