// Package sip 实现 GB/T 28181 所需的 SIP 协议栈：报文、传输、事务、鉴权、证据。
//
// 移植自 PyGBSentry app/sip/*（纯 Python 栈），Go 版改造要点：
//   - 外层"宽松解析守卫"：任何字段异常不返回 error，只产出 ParseDeviation
//     解析偏差事实——诊断工具解析失败本身即证据（spec 4.4.4）。
//   - 证据必须使用原始字节：SipMessage 保留 Raw，禁止用序列化结果充当原文。
package sip

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Deviation 是宽松解析守卫产出的解析偏差事实（诊断证据，非异常）。
type Deviation struct {
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Position string `json:"position,omitempty"`
}

const maxMessageBytes = 1 << 20 // 1MB 上限，防畸形大包拖垮内存

// compactFormMap 为 RFC 3261 紧凑头映射。
var compactFormMap = map[string]string{
	"v": "via", "i": "call-id", "t": "to", "f": "from", "m": "contact",
	"u": "allow-events", "e": "content-encoding", "l": "content-length",
	"c": "content-type", "s": "subject", "k": "supported", "r": "refer-to",
	"o": "event", "b": "referred-by", "n": "identity", "d": "request-disposition",
	"x": "session-expires", "j": "reject-contact",
}

// normHeaderName 归一化头部名：小写 + 紧凑形式展开。
func normHeaderName(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	if v, ok := compactFormMap[key]; ok {
		return v
	}
	return key
}

// header 是单条头部（保留原始大小写以便序列化回放）。
type header struct {
	Name  string
	Value string
}

// Headers 为有序多值头部容器（dict 风格访问 + 规范名归一）。
type Headers struct {
	list []header
}

// Add 追加一条头部（多值语义）。
func (h *Headers) Add(name, value string) {
	h.list = append(h.list, header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
}

// Set 覆盖同名全部头部。
func (h *Headers) Set(name, value string) {
	key := normHeaderName(name)
	for i := range h.list {
		if normHeaderName(h.list[i].Name) == key {
			h.list[i].Value = strings.TrimSpace(value)
			// 删除后续同名
			kept := h.list[:i+1]
			for j := i + 1; j < len(h.list); j++ {
				if normHeaderName(h.list[j].Name) != key {
					kept = append(kept, h.list[j])
				}
			}
			h.list = kept
			return
		}
	}
	h.Add(name, value)
}

// Del 删除同名全部头部。
func (h *Headers) Del(name string) {
	key := normHeaderName(name)
	kept := h.list[:0]
	for _, hh := range h.list {
		if normHeaderName(hh.Name) != key {
			kept = append(kept, hh)
		}
	}
	h.list = kept
}

// Get 取第一个同名头部的值（规范名归一，无则空串）。
func (h *Headers) Get(name string) string {
	key := normHeaderName(name)
	for _, hh := range h.list {
		if normHeaderName(hh.Name) == key {
			return hh.Value
		}
	}
	return ""
}

// GetAll 取同名全部值。
func (h *Headers) GetAll(name string) []string {
	key := normHeaderName(name)
	var out []string
	for _, hh := range h.list {
		if normHeaderName(hh.Name) == key {
			out = append(out, hh.Value)
		}
	}
	return out
}

// Has 报告是否存在同名头部。
func (h *Headers) Has(name string) bool { return h.Get(name) != "" }

// Keys 返回全部头部名（按出现序，不去重）。
func (h *Headers) Keys() []string {
	out := make([]string, 0, len(h.list))
	for _, hh := range h.list {
		out = append(out, hh.Name)
	}
	return out
}

// Len 返回头部条数。
func (h *Headers) Len() int { return len(h.list) }

// Map 返回 规范名→首个值 的映射（供 FactSet/规则 DSL 使用）。
func (h *Headers) Map() map[string]string {
	m := make(map[string]string, len(h.list))
	for _, hh := range h.list {
		k := normHeaderName(hh.Name)
		if _, ok := m[k]; !ok {
			m[k] = hh.Value
		}
	}
	return m
}

// SipMessage 为解析后的 SIP 报文（请求或响应）。
type SipMessage struct {
	IsRequest    bool
	Method       string
	URI          string
	Version      string
	StatusCode   int
	ReasonPhrase string

	Headers Headers
	Body    []byte
	Raw     []byte // 原始字节（证据链必须使用原始字节）

	Deviations []Deviation
}

func (m *SipMessage) addDev(kind, detail string) {
	m.Deviations = append(m.Deviations, Deviation{Kind: kind, Detail: detail})
}

// Parse 解析 SIP 报文；永不返回 nil、永不 panic，异常均进 Deviations。
func Parse(raw []byte) *SipMessage {
	msg := &SipMessage{Version: "SIP/2.0", Raw: raw}
	if len(raw) == 0 {
		msg.addDev("empty", "空报文")
		return msg
	}
	if len(raw) > maxMessageBytes {
		msg.addDev("size", "报文超过 1MB 上限")
		raw = raw[:maxMessageBytes]
	}
	headEnd, bodyStart := -1, -1
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			headEnd, bodyStart = i, i+4
			break
		}
	}
	if headEnd < 0 {
		for i := 0; i+1 < len(raw); i++ {
			if raw[i] == '\n' && raw[i+1] == '\n' {
				headEnd, bodyStart = i, i+2
				break
			}
		}
	}
	head := raw
	if headEnd >= 0 {
		head = raw[:headEnd]
		msg.Body = raw[bodyStart:]
	} else if len(raw) > 0 && !looksLikeSIP(raw) {
		msg.addDev("framing", "未找到头部/报文分隔符")
	}
	msg.parseStartAndHeaders(head)
	msg.applyContentLength()
	return msg
}

func looksLikeSIP(raw []byte) bool {
	n := len(raw)
	if n > 64 {
		n = 64
	}
	s := strings.ToUpper(string(raw[:n]))
	for _, p := range []string{"SIP/", "REGISTER", "INVITE", "MESSAGE", "ACK", "BYE", "CANCEL", "NOTIFY", "SUBSCRIBE"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (m *SipMessage) parseStartAndHeaders(head []byte) {
	text := strings.ReplaceAll(string(head), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	// SIP 头部允许以空格/Tab 续行，先合并。
	merged := make([]string, 0, len(lines))
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if (ln[0] == ' ' || ln[0] == '\t') && len(merged) > 0 {
			merged[len(merged)-1] += " " + strings.TrimSpace(ln)
		} else {
			merged = append(merged, ln)
		}
	}
	if len(merged) == 0 {
		m.addDev("start_line", "无起始行")
		return
	}
	m.parseStartLine(merged[0])
	for _, ln := range merged[1:] {
		idx := strings.Index(ln, ":")
		if idx <= 0 {
			m.addDev("header_line", "无法识别的头部行: "+truncate(ln, 80))
			continue
		}
		m.Headers.Add(ln[:idx], ln[idx+1:])
	}
}

func (m *SipMessage) parseStartLine(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		m.addDev("start_line", "起始行为空")
		return
	}
	up := strings.ToUpper(s)
	if strings.HasPrefix(up, "SIP/") || strings.HasPrefix(up, "SIP 2.0") {
		parts := strings.SplitN(s, " ", 3)
		m.Version = parts[0]
		if len(parts) >= 2 {
			code, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || code < 100 || code > 999 {
				m.StatusCode = 0
				m.addDev("start_line", "非数字状态码: "+parts[1])
			} else {
				m.StatusCode = code
			}
		} else {
			m.addDev("start_line", "响应行缺少状态码")
		}
		if len(parts) >= 3 {
			m.ReasonPhrase = parts[2]
		}
		return
	}
	parts := strings.Fields(s)
	if len(parts) >= 3 && strings.HasPrefix(strings.ToUpper(parts[2]), "SIP/") {
		m.IsRequest = true
		m.Method = strings.ToUpper(parts[0])
		m.URI = parts[1]
		m.Version = parts[2]
		return
	}
	m.Version = s
	m.addDev("start_line", "无法识别的起始行: "+truncate(s, 80))
}

// applyContentLength 依据 Content-Length 裁剪/校验 body 长度。
func (m *SipMessage) applyContentLength() {
	cl := m.Headers.Get("content-length")
	if cl == "" {
		if len(m.Body) > 0 {
			m.addDev("content_length", "有报文体但缺少 Content-Length")
		}
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(cl))
	if err != nil || n < 0 {
		m.addDev("content_length", "Content-Length 非法: "+cl)
		return
	}
	if n != len(m.Body) {
		if n < len(m.Body) {
			m.Body = m.Body[:n]
		}
		m.addDev("content_length", "报文体长度与 Content-Length 不符")
	}
}

// String 序列化为报文（自动补 Content-Length）。
func (m *SipMessage) String() string {
	var b strings.Builder
	if m.IsRequest {
		method := m.Method
		if method == "" {
			method = "REGISTER"
		}
		ver := m.Version
		if ver == "" {
			ver = "SIP/2.0"
		}
		b.WriteString(method + " " + m.URI + " " + ver + "\r\n")
	} else {
		code := m.StatusCode
		if code == 0 {
			code = 200
		}
		reason := m.ReasonPhrase
		if reason == "" {
			reason = DefaultReason(code)
		}
		ver := m.Version
		if ver == "" {
			ver = "SIP/2.0"
		}
		b.WriteString(ver + " " + strconv.Itoa(code) + " " + reason + "\r\n")
	}
	for _, hh := range m.Headers.list {
		if normHeaderName(hh.Name) == "content-length" {
			continue // 序列化时统一重写
		}
		b.WriteString(hh.Name + ": " + hh.Value + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(m.Body)) + "\r\n")
	b.WriteString("\r\n")
	b.Write(m.Body)
	return b.String()
}

// Bytes 序列化为字节。
func (m *SipMessage) Bytes() []byte { return []byte(m.String()) }

// CallID 返回 Call-ID。
func (m *SipMessage) CallID() string { return m.Headers.Get("call-id") }

// CSeq 返回 (序号, 方法)。
func (m *SipMessage) CSeq() (int, string) {
	v := m.Headers.Get("cseq")
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return 0, ""
	}
	n, _ := strconv.Atoi(parts[0])
	method := ""
	if len(parts) > 1 {
		method = strings.ToUpper(parts[1])
	}
	return n, method
}

// ViaList 返回全部 Via 值。
func (m *SipMessage) ViaList() []string { return m.Headers.GetAll("via") }

// URIUser 从地址头（From/To/Contact）提取 user 部分。
func URIUser(headerValue string) string {
	i := strings.Index(headerValue, "sip:")
	if i < 0 {
		return ""
	}
	rest := headerValue[i+4:]
	end := len(rest)
	for j := 0; j < len(rest); j++ {
		if rest[j] == '@' || rest[j] == ';' || rest[j] == '>' {
			end = j
			break
		}
	}
	return rest[:end]
}

// AddrTag 提取地址头中的 tag 参数。
func AddrTag(headerValue string) string {
	lower := strings.ToLower(headerValue)
	i := strings.Index(lower, "tag=")
	if i < 0 {
		return ""
	}
	rest := headerValue[i+4:]
	for j := 0; j < len(rest); j++ {
		if rest[j] == ';' {
			return rest[:j]
		}
	}
	return rest
}

// BodyText 返回报文体文本。
func (m *SipMessage) BodyText() string { return string(m.Body) }

// IsXML 判定报文体是否为 XML（国标 MESSAGE/NOTIFY 语义）。
func (m *SipMessage) IsXML() bool {
	ct := strings.ToLower(m.Headers.Get("content-type"))
	return strings.Contains(ct, "xml") || strings.HasPrefix(strings.TrimLeft(m.BodyText(), " \t\r\n"), "<")
}

// DetectXMLEncoding 从 XML prolog 提取 encoding 声明（非 UTF-8 是目录诊断项）。
func DetectXMLEncoding(body string) string {
	t := strings.TrimLeft(body, " \t\r\n")
	if !strings.HasPrefix(t, "<?xml") {
		return ""
	}
	end := strings.Index(t, "?>")
	if end < 0 || end > 200 {
		return ""
	}
	seg := t[:end]
	lower := strings.ToLower(seg)
	i := strings.Index(lower, "encoding=")
	if i < 0 {
		return ""
	}
	rest := seg[i+len("encoding="):]
	rest = strings.TrimLeft(rest, " \t")
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' || rest[0] == '\'' {
		q := rest[0]
		for j := 1; j < len(rest); j++ {
			if rest[j] == q {
				return rest[1:j]
			}
		}
		return rest[1:]
	}
	for j := 0; j < len(rest); j++ {
		switch rest[j] {
		case ' ', '\t', '\r', '\n', '?':
			return rest[:j]
		}
	}
	return rest
}

// CreateResponse 基于请求构造响应（Via 原样回拷、From/To/Call-ID/CSeq 透传）。
func CreateResponse(req *SipMessage, code int, reason string) *SipMessage {
	resp := &SipMessage{Version: "SIP/2.0", StatusCode: code}
	if reason == "" {
		reason = DefaultReason(code)
	}
	resp.ReasonPhrase = reason
	for _, via := range req.ViaList() {
		resp.Headers.Add("Via", via)
	}
	resp.Headers.Set("From", req.Headers.Get("from"))
	resp.Headers.Set("To", req.Headers.Get("to"))
	resp.Headers.Set("Call-ID", req.CallID())
	if cseq := req.Headers.Get("cseq"); cseq != "" {
		resp.Headers.Set("CSeq", cseq)
	}
	return resp
}

// PatchViaReceived 按实际来源地址修补 Via 的 received/rport（NAT 判据）。
func PatchViaReceived(viaValue string, ip string, port int) string {
	if viaValue == "" {
		return viaValue
	}
	parts := strings.Split(viaValue, ";")
	out := make([]string, 0, len(parts)+2)
	rportAdded := false
	hadRport := strings.Contains(strings.ToLower(viaValue), "rport")
	for _, part := range parts {
		p := strings.TrimSpace(strings.ToLower(part))
		switch {
		case p == "rport" || strings.HasPrefix(p, "rport="):
			out = append(out, "rport="+strconv.Itoa(port))
			rportAdded = true
		case strings.HasPrefix(p, "received="):
			// 丢弃旧 received，统一由本端回填
		default:
			out = append(out, strings.TrimSpace(part))
		}
	}
	out = append(out, "received="+ip)
	if !rportAdded && hadRport {
		out = append(out, "rport="+strconv.Itoa(port))
	}
	return strings.Join(out, ";")
}

// StableToTag 按 hash 生成稳定 to-tag，保证重传幂等。
func StableToTag(callID, cseq, method string) string {
	sum := sha256.Sum256([]byte(callID + "|" + cseq + "|" + method))
	return hex.EncodeToString(sum[:])[:8]
}

// DefaultReason 常用状态码默认 reason。
func DefaultReason(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 200:
		return "OK"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 486:
		return "Busy Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	case 600:
		return "Busy Everywhere"
	}
	return ""
}

// NewRequest 构造最小请求（供模拟摄像头/平台侧体检使用）。
func NewRequest(method, uri, callID string, cseq int) *SipMessage {
	m := &SipMessage{IsRequest: true, Method: strings.ToUpper(method), URI: uri, Version: "SIP/2.0"}
	m.Headers.Set("Call-ID", callID)
	m.Headers.Set("CSeq", strconv.Itoa(cseq)+" "+m.Method)
	return m
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
