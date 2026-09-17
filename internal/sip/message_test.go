package sip

import (
	"strings"
	"testing"
)

const sampleRegister = "REGISTER sip:34020000002000000001 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 192.168.1.64:5060;rport;branch=z9hG4bK123\r\n" +
	"From: <sip:34020000001320000001@34020000002000000001>;tag=abc\r\n" +
	"To: <sip:34020000001320000001@34020000002000000001>\r\n" +
	"Call-ID: call-1\r\n" +
	"CSeq: 1 REGISTER\r\n" +
	"Max-Forwards: 70\r\n" +
	"Contact: <sip:34020000001320000001@192.168.1.64:5060>\r\n" +
	"Expires: 3600\r\n" +
	"Content-Length: 0\r\n\r\n"

func TestParseRequest(t *testing.T) {
	m := Parse([]byte(sampleRegister))
	if m == nil || !m.IsRequest {
		t.Fatalf("应解析为请求")
	}
	if m.Method != "REGISTER" || m.URI != "sip:34020000002000000001" {
		t.Errorf("Method/URI = %s/%s", m.Method, m.URI)
	}
	if m.CallID() != "call-1" {
		t.Errorf("CallID = %q", m.CallID())
	}
	if n, method := m.CSeq(); n != 1 || method != "REGISTER" {
		t.Errorf("CSeq = %d,%s", n, method)
	}
	if len(m.Deviations) != 0 {
		t.Errorf("合法报文不应有偏差: %v", m.Deviations)
	}
	if user := URIUser(m.Headers.Get("from")); user != "34020000001320000001" {
		t.Errorf("URIUser = %q", user)
	}
}

func TestParseResponse(t *testing.T) {
	raw := "SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 1.2.3.4:5060\r\n" +
		"WWW-Authenticate: Digest realm=\"34020000002000000001\", nonce=\"abc123\", algorithm=MD5\r\n" +
		"Content-Length: 0\r\n\r\n"
	m := Parse([]byte(raw))
	if m.IsRequest || m.StatusCode != 401 || m.ReasonPhrase != "Unauthorized" {
		t.Fatalf("响应解析错误: %+v", m)
	}
	p := ParseAuthParams(m.Headers.Get("www-authenticate"))
	if p["realm"] != "34020000002000000001" || p["nonce"] != "abc123" || p["algorithm"] != "MD5" {
		t.Errorf("挑战参数解析错误: %v", p)
	}
}

func TestCompactHeaderForm(t *testing.T) {
	raw := "REGISTER sip:x SIP/2.0\r\nv: SIP/2.0/UDP 1.1.1.1:5060\r\ni: cid-9\r\nt: <sip:u@x>\r\nl: 0\r\n\r\n"
	m := Parse([]byte(raw))
	if m.CallID() != "cid-9" {
		t.Errorf("紧凑 Call-ID 未展开: %q", m.CallID())
	}
	if len(m.ViaList()) != 1 {
		t.Errorf("紧凑 Via 未展开")
	}
}

func TestLenientGuardNeverErrors(t *testing.T) {
	bad := [][]byte{
		[]byte(""),
		[]byte("garbage without crlfcrlf"),
		[]byte("SIP/2.0 abc weird\r\nbroken line\r\n\r\n"),
		[]byte("REGISTER sip:x SIP/2.0\r\nContent-Length: 99\r\n\r\nshort"),
		[]byte("REGISTER sip:x SIP/2.0\r\nno-colon-line\r\n\r\n"),
	}
	for _, b := range bad {
		m := Parse(b)
		if m == nil {
			t.Fatalf("Parse 不应返回 nil: %q", b)
		}
		if len(m.Deviations) == 0 && len(b) > 0 {
			t.Errorf("畸形报文应产出偏差事实: %q", b)
		}
	}
}

func TestCreateResponseAndSerialize(t *testing.T) {
	req := Parse([]byte(sampleRegister))
	resp := CreateResponse(req, 200, "")
	resp.Headers.Set("To", req.Headers.Get("to")+";tag="+StableToTag(req.CallID(), "1 REGISTER", "REGISTER"))
	out := resp.String()
	if !strings.Contains(out, "SIP/2.0 200 OK") {
		t.Errorf("序列化缺少状态行: %q", out)
	}
	if !strings.Contains(out, "Content-Length: 0") {
		t.Errorf("序列化应自动补 Content-Length")
	}
	if !strings.Contains(out, "Via: SIP/2.0/UDP 192.168.1.64:5060") {
		t.Errorf("Via 应原样回拷")
	}
}

func TestStableToTagIdempotent(t *testing.T) {
	a := StableToTag("call-1", "1 REGISTER", "REGISTER")
	b := StableToTag("call-1", "1 REGISTER", "REGISTER")
	if a != b || len(a) != 8 {
		t.Errorf("StableToTag 应幂等且 8 位: %q vs %q", a, b)
	}
}

func TestPatchViaReceived(t *testing.T) {
	got := PatchViaReceived("SIP/2.0/UDP 192.168.1.64:5060;rport;branch=z9hG4bK1", "10.0.0.8", 51000)
	if !strings.Contains(got, "rport=51000") || !strings.Contains(got, "received=10.0.0.8") {
		t.Errorf("PatchViaReceived 错误: %q", got)
	}
	got2 := PatchViaReceived("SIP/2.0/UDP 192.168.1.64:5060;branch=z9hG4bK2", "10.0.0.8", 51000)
	if !strings.Contains(got2, "received=10.0.0.8") {
		t.Errorf("无 rport 时仍应补 received: %q", got2)
	}
}

func TestDetectXMLEncoding(t *testing.T) {
	if got := DetectXMLEncoding(`<?xml version="1.0" encoding="UTF-8"?><Notify/>`); got != "UTF-8" {
		t.Errorf("encoding = %q, want UTF-8", got)
	}
	if got := DetectXMLEncoding(`<?xml version='1.0' encoding='GB2312'?><Notify/>`); got != "GB2312" {
		t.Errorf("单引号 encoding = %q", got)
	}
	if got := DetectXMLEncoding(`<Notify/>`); got != "" {
		t.Errorf("无 prolog 应返回空: %q", got)
	}
}

func TestXMLTagValue(t *testing.T) {
	body := `<?xml version="1.0"?><Notify><CmdType>Keepalive</CmdType><SN>3</SN><DeviceID>34020000001320000001</DeviceID></Notify>`
	if got := XMLTagValue(body, "CmdType"); got != "Keepalive" {
		t.Errorf("CmdType = %q", got)
	}
	if got := XMLTagValue(body, "SN"); got != "3" {
		t.Errorf("SN = %q", got)
	}
	if got := XMLTagValue(body, "NotExist"); got != "" {
		t.Errorf("不存在标签应为空")
	}
}

func TestRawBytesPreserved(t *testing.T) {
	m := Parse([]byte(sampleRegister))
	if string(m.Raw) != sampleRegister {
		t.Errorf("Raw 必须保留原始字节（证据链约束）")
	}
}
