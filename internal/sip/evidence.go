package sip

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Evidence 为一条报文级证据（内存态；序列化见 report 包）。
type Evidence struct {
	Direction  string // in / out
	CapturedAt time.Time
	Proto      string // udp / tcp
	Addr       string // 对端地址
	RawText    string // 原始报文文本
	RawSHA256  string // 原始字节指纹
	Size       int
	CallID     string
	Stage      string
}

// EvidenceRecorder 记录收发报文证据。
// 约束（spec 4.3.6/4.4.4）：原文保全、敏感头脱敏、按 call_id 归组、SHA-256 指纹。
type EvidenceRecorder struct {
	mu       sync.Mutex
	items    []Evidence
	maxKeep  int
	redacted bool
}

// NewEvidenceRecorder 创建记录器（maxKeep<=0 表示不限）。
func NewEvidenceRecorder(maxKeep int) *EvidenceRecorder {
	if maxKeep <= 0 {
		maxKeep = 5000
	}
	return &EvidenceRecorder{maxKeep: maxKeep, redacted: true}
}

// redactHeaderNames 需要脱敏的头部（spec 4.3.6 敏感信息白名单校验）。
var redactHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
}

// record 内部登记一条证据。
func (r *EvidenceRecorder) record(direction, proto, addr string, raw []byte, ts time.Time) Evidence {
	text := string(raw)
	callID := ""
	if msg := Parse(raw); msg != nil {
		callID = msg.CallID()
	}
	if r.redacted {
		text = RedactAuth(text)
	}
	ev := Evidence{
		Direction:  direction,
		CapturedAt: ts,
		Proto:      proto,
		Addr:       addr,
		RawText:    text,
		RawSHA256:  SHA256Hex(raw),
		Size:       len(raw),
		CallID:     callID,
	}
	r.mu.Lock()
	r.items = append(r.items, ev)
	if len(r.items) > r.maxKeep {
		r.items = r.items[len(r.items)-r.maxKeep:]
	}
	r.mu.Unlock()
	return ev
}

// RecordIn 登记入站证据（调用方传入到达时刻）。
func (r *EvidenceRecorder) RecordIn(pkt Packet) Evidence {
	return r.record("in", pkt.Proto, pkt.Src, pkt.Raw, pkt.TS)
}

// RecordOut 登记出站证据。
func (r *EvidenceRecorder) RecordOut(proto, addr string, raw []byte) Evidence {
	return r.record("out", proto, addr, raw, time.Now())
}

// All 返回证据快照。
func (r *EvidenceRecorder) All() []Evidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Evidence, len(r.items))
	copy(out, r.items)
	return out
}

// ByCallID 返回指定 call-id 的证据。
func (r *EvidenceRecorder) ByCallID(callID string) []Evidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Evidence
	for _, ev := range r.items {
		if ev.CallID == callID {
			out = append(out, ev)
		}
	}
	return out
}

// Count 返回证据条数。
func (r *EvidenceRecorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

// SHA256Hex 计算字节指纹。
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RedactAuth 擦除 Authorization / Proxy-Authorization 头部值。
func RedactAuth(text string) string {
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		idx := strings.Index(ln, ":")
		if idx <= 0 {
			continue
		}
		if redactHeaderNames[normHeaderName(ln[:idx])] {
			lines[i] = ln[:idx] + ": [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}

// MaxInPacketSize 返回入站最大报文长度（UDP 大报文分片判定输入）。
func (r *EvidenceRecorder) MaxInPacketSize() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := 0
	for _, ev := range r.items {
		if ev.Direction == "in" && ev.Size > m {
			m = ev.Size
		}
	}
	return m
}
