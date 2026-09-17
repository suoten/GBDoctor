package sip

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// md5Hex 计算 MD5 摘要十六进制串。
func md5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// 鉴权算法标识（GB28181 常见：MD5；2022 新标引入 SHA-256/SM3）。
const (
	AlgoMD5    = "MD5"
	AlgoSHA256 = "SHA-256"
	AlgoSM3    = "SM3"
)

// NormalizeAlgorithm 归一化算法名；未知返回空串。
func NormalizeAlgorithm(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "MD5":
		return AlgoMD5
	case "SHA-256", "SHA256", "SHA_256":
		return AlgoSHA256
	case "SM3", "SM3-USER", "SM3USER":
		return AlgoSM3
	}
	return ""
}

func digestHex(alg string, data []byte) string {
	switch alg {
	case AlgoSHA256:
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	case AlgoSM3:
		return SM3Hex(data)
	default: // MD5 及未声明算法按国标惯例默认 MD5
		return md5Hex(data)
	}
}

// HA1 = H(username:realm:password)
func computeHA1(user, realm, pass, alg string) string {
	return digestHex(alg, []byte(user+":"+realm+":"+pass))
}

// HA2 = H(method:uri)
func computeHA2(method, uri, alg string) string {
	return digestHex(alg, []byte(method+":"+uri))
}

// ComputeDigestResponse 计算 Digest response（支持 qop=auth 与无 qop 两种形态）。
func ComputeDigestResponse(user, realm, pass, method, uri, nonce, nc, cnonce, qop, alg string) string {
	ha1 := computeHA1(user, realm, pass, alg)
	ha2 := computeHA2(method, uri, alg)
	if strings.EqualFold(strings.TrimSpace(qop), "auth") {
		return digestHex(alg, []byte(ha1+":"+nonce+":"+nc+":"+cnonce+":auth:"+ha2))
	}
	return digestHex(alg, []byte(ha1+":"+nonce+":"+ha2))
}

// ParseAuthParams 解析 `Digest k="v", k=v` 形式的挑战/应答参数。
func ParseAuthParams(headerValue string) map[string]string {
	params := map[string]string{}
	h := strings.TrimSpace(headerValue)
	if h == "" {
		return params
	}
	lower := strings.ToLower(h)
	if strings.HasPrefix(lower, "digest") {
		h = strings.TrimSpace(h[6:])
	}
	// 逐段扫描，支持带引号值。
	i := 0
	for i < len(h) {
		// key
		start := i
		for i < len(h) && h[i] != '=' && h[i] != ',' {
			i++
		}
		key := strings.ToLower(strings.TrimSpace(h[start:i]))
		if i >= len(h) || h[i] == ',' {
			i++
			continue
		}
		i++ // 跳过 '='
		var val string
		if i < len(h) && (h[i] == '"' || h[i] == '\'') {
			q := h[i]
			i++
			vs := i
			for i < len(h) && h[i] != q {
				i++
			}
			val = h[vs:i]
			if i < len(h) {
				i++ // 跳过收尾引号
			}
		} else {
			vs := i
			for i < len(h) && h[i] != ',' {
				i++
			}
			val = strings.TrimSpace(h[vs:i])
		}
		if key != "" {
			params[key] = val
		}
		for i < len(h) && (h[i] == ' ' || h[i] == ',') {
			i++
		}
	}
	return params
}

// Challenge 为一次 401 质询。
type Challenge struct {
	Realm     string
	Nonce     string
	Algorithm string
	Opaque    string
}

// HeaderValue 输出 WWW-Authenticate 头部值。
func (c Challenge) HeaderValue() string {
	var b strings.Builder
	b.WriteString(`Digest realm="` + c.Realm + `", nonce="` + c.Nonce + `"`)
	if c.Algorithm != "" {
		b.WriteString(`, algorithm=` + c.Algorithm)
	}
	if c.Opaque != "" {
		b.WriteString(`, opaque="` + c.Opaque + `"`)
	}
	return b.String()
}

// nonceEntry 记录已签发 nonce（防重放 + 算法/realm 跟踪）。
type nonceEntry struct {
	deviceID   string
	realm      string
	alg        string
	issuedAt   time.Time
	challenged int
}

// DigestVerifier 管理质询/应答（会话内存表，进程内）。
// 并发安全：UDP/TCP 双监听时多个 dispatch goroutine 会并发调用 Verify/NewNonce。
type DigestVerifier struct {
	mu      sync.Mutex
	secret  []byte
	ttl     time.Duration
	nonces  map[string]*nonceEntry
	failCnt map[string]int // device_id -> 连续鉴权失败次数
}

// NewDigestVerifier 创建验证器（secret 用于派生 nonce 熵）。
func NewDigestVerifier(secret []byte) *DigestVerifier {
	if len(secret) == 0 {
		secret = []byte("gbdoctor-nonce")
	}
	return &DigestVerifier{
		secret:  secret,
		ttl:     5 * time.Minute,
		nonces:  map[string]*nonceEntry{},
		failCnt: map[string]int{},
	}
}

// NewNonce 签发新 nonce 并登记（幂等注册依赖同一 nonce）。
func (v *DigestVerifier) NewNonce(deviceID, realm, alg string) string {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	nonce := hex.EncodeToString(buf[:])
	v.mu.Lock()
	v.nonces[nonce] = &nonceEntry{deviceID: deviceID, realm: realm, alg: alg, issuedAt: time.Now()}
	v.mu.Unlock()
	return nonce
}

// NewChallenge 构造质询（自动签发 nonce）。
func (v *DigestVerifier) NewChallenge(deviceID, realm, alg string) Challenge {
	return Challenge{
		Realm:     realm,
		Nonce:     v.NewNonce(deviceID, realm, alg),
		Algorithm: alg,
	}
}

// FailureCount 返回设备连续鉴权失败次数。
func (v *DigestVerifier) FailureCount(deviceID string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.failCnt[deviceID]
}

// ResetFailures 清零失败计数（200 OK 时调用）。
func (v *DigestVerifier) ResetFailures(deviceID string) {
	v.mu.Lock()
	delete(v.failCnt, deviceID)
	v.mu.Unlock()
}

// Verify 校验 Authorization 头。
// 返回 (是否通过, 设备声明算法, 失败类别)。
// 失败类别：""（通过）/ no_header / bad_params / unknown_nonce / stale_nonce / mismatch / unknown_algorithm。
func (v *DigestVerifier) Verify(authHeader, method, requestURI, user, pass string) (bool, string, string) {
	if strings.TrimSpace(authHeader) == "" {
		return false, "", "no_header"
	}
	p := ParseAuthParams(authHeader)
	if len(p) == 0 {
		return false, "", "bad_params"
	}
	nonce := p["nonce"]
	if nonce == "" {
		return false, "", "bad_params"
	}
	v.mu.Lock()
	entry, ok := v.nonces[nonce]
	if ok && time.Since(entry.issuedAt) > v.ttl {
		delete(v.nonces, nonce)
		ok = false
	}
	v.mu.Unlock()
	if !ok {
		return false, p["algorithm"], "unknown_nonce"
	}

	declared := NormalizeAlgorithm(p["algorithm"])
	if p["algorithm"] != "" && declared == "" {
		// 设备声明了本工具不识别的算法：记录为算法事实，不直接判失败
		declared = strings.ToUpper(p["algorithm"])
	}
	alg := declared
	if alg == "" {
		alg = AlgoMD5 // 国标惯例：未声明默认 MD5
	}

	uri := p["uri"]
	if uri == "" {
		uri = requestURI
	}
	realm := p["realm"]
	if realm == "" {
		realm = entry.realm
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	response := ComputeDigestResponse(user, realm, pass, method, uri, nonce, p["nc"], p["cnonce"], p["qop"], alg)
	if !strings.EqualFold(response, p["response"]) {
		v.failCnt[entry.deviceID]++
		return false, declared, "mismatch"
	}
	v.failCnt[entry.deviceID] = 0
	return true, declared, ""
}
