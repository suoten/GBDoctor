package sip

import (
	"fmt"
	"sync"
	"time"
)

// RegisterSession 为已注册设备的内存会话。
type RegisterSession struct {
	DeviceID         string
	Host             string
	Port             int
	Transport        string
	Algorithm        string // 鉴权实际使用算法
	RegisteredAt     time.Time
	Expires          int
	LastRegisterAddr string
	RegisterCount    int
	LastKeepaliveAt  time.Time
	KeepaliveCount   int
}

// RegisterFact 为注册环节结构化事实（供检测器/规则引擎使用）。
type RegisterFact struct {
	Kind          string // registered / challenge / auth_fail / deregister
	DeviceID      string
	Source        string
	Algorithm     string // 设备实际使用/声明的算法
	DeclaredAlg   string // 设备 Authorization 中声明的算法
	Expires       int
	ViaAddr       string
	ContactAddr   string
	ReceivedAddr  string
	NATMismatch   bool
	DeviceIDValid bool
	FailureKind   string // unknown_nonce / stale_nonce / mismatch / no_header / bad_params
	MaxInSize     int
	TS            time.Time
	Raw           []byte
}

// KeepaliveFact 为心跳事实。
type KeepaliveFact struct {
	DeviceID string
	Source   string
	XML      string
	OK       bool
	TS       time.Time
}

// MessageFact 为通用 MESSAGE 事实（目录应答等）。
type MessageFact struct {
	DeviceID string
	CmdType  string
	SN       string
	Body     string
	Source   string
	TS       time.Time
}

// RoleConfig 为角色配置。
type RoleConfig struct {
	Host              string // 默认 0.0.0.0
	Port              int    // 默认 5060
	ServerID          string // 必填（SIP 服务器编码）
	Password          string
	Realm             string // 默认取 ServerID
	ChallengeAlg      string // 默认 MD5；SM3 用于算法探测
	ListenTCP         bool
	RegisterExpires   int // 默认 3600
	NonceSecret       []byte
	MaxPacketSizeWarn int // UDP 大报文告警阈值，默认 1300
}

// DeviceSideRole 模拟上级平台：接收注册/心跳/目录应答，输出结构化事实。
type DeviceSideRole struct {
	cfg      RoleConfig
	udp      *UDPTransport
	tcp      *TCPTransport
	auth     *DigestVerifier
	ev       *EvidenceRecorder
	sessions map[string]*RegisterSession

	pendingInvites  map[string]chan *SipMessage
	pendingMessages map[string]chan *SipMessage

	// 平台侧 CSeq 计数器（实例级：多实例并发运行时不能共享包级变量）
	platformCSeq int

	// 多回调列表（V1.2 架构重构：单回调 → 多回调，解决覆盖问题）
	onRegister   []func(RegisterFact)
	onKeepalive  []func(KeepaliveFact)
	onMessage    []func(MessageFact)
	onCatalog    []func(CatalogFact)
	onDeviceInfo []func(DeviceInfoFact)
	onAlarm      []func(AlarmFact)
	onRecordInfo []func(RecordInfoFact)
	onInvite     []func(InviteFact)
	onPTZ        []func(PTZFact)

	// 报文捕获（用于内置抓包功能）
	capturedPackets []CapturedPacket

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
}

// CapturedPacket 为捕获的 SIP 报文（入站或出站）。
type CapturedPacket struct {
	TS        time.Time
	Direction string // "in" 或 "out"
	Src       string
	Dst       string
	Proto     string
	Raw       []byte
}

// NewDeviceSideRole 创建模拟上级平台角色（补默认值）。
// 注意：Port=0 表示由操作系统随机分配端口，不替换为 5060，
// 避免并发测试时多实例竞争同一端口。CLI 层面通过 flag 默认值设 5060。
func NewDeviceSideRole(cfg RoleConfig) *DeviceSideRole {
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Realm == "" {
		cfg.Realm = cfg.ServerID
	}
	if cfg.ChallengeAlg == "" {
		cfg.ChallengeAlg = AlgoMD5
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = 3600
	}
	if cfg.MaxPacketSizeWarn == 0 {
		cfg.MaxPacketSizeWarn = 1300
	}
	return &DeviceSideRole{
		cfg:      cfg,
		auth:     NewDigestVerifier(cfg.NonceSecret),
		ev:       NewEvidenceRecorder(5000),
		sessions: map[string]*RegisterSession{},
		stopCh:   make(chan struct{}),
	}
}

// OnRegister 注册事实回调（多回调，追加不覆盖）。
func (r *DeviceSideRole) OnRegister(fn func(RegisterFact)) {
	r.mu.Lock()
	r.onRegister = append(r.onRegister, fn)
	r.mu.Unlock()
}

// OnKeepalive 心跳事实回调（多回调，追加不覆盖）。
func (r *DeviceSideRole) OnKeepalive(fn func(KeepaliveFact)) {
	r.mu.Lock()
	r.onKeepalive = append(r.onKeepalive, fn)
	r.mu.Unlock()
}

// OnMessage MESSAGE 事实回调（多回调，追加不覆盖）。
func (r *DeviceSideRole) OnMessage(fn func(MessageFact)) {
	r.mu.Lock()
	r.onMessage = append(r.onMessage, fn)
	r.mu.Unlock()
}

// OnCatalog 目录应答回调（多回调，追加不覆盖）。
// 返回注销函数；长驻服务中每次体检必须调用注销，否则回调列表无限增长。
func (r *DeviceSideRole) OnCatalog(fn func(CatalogFact)) func() {
	r.mu.Lock()
	r.onCatalog = append(r.onCatalog, fn)
	idx := len(r.onCatalog) - 1
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if idx < len(r.onCatalog) {
			r.onCatalog[idx] = nil
		}
		r.mu.Unlock()
	}
}

// OnDeviceInfo 设备信息应答回调（多回调，追加不覆盖）。
// 返回注销函数。
func (r *DeviceSideRole) OnDeviceInfo(fn func(DeviceInfoFact)) func() {
	r.mu.Lock()
	r.onDeviceInfo = append(r.onDeviceInfo, fn)
	idx := len(r.onDeviceInfo) - 1
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if idx < len(r.onDeviceInfo) {
			r.onDeviceInfo[idx] = nil
		}
		r.mu.Unlock()
	}
}

// OnAlarm 报警通知回调（多回调，追加不覆盖）。
// 返回注销函数。
func (r *DeviceSideRole) OnAlarm(fn func(AlarmFact)) func() {
	r.mu.Lock()
	r.onAlarm = append(r.onAlarm, fn)
	idx := len(r.onAlarm) - 1
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if idx < len(r.onAlarm) {
			r.onAlarm[idx] = nil
		}
		r.mu.Unlock()
	}
}

// OnRecordInfo 录像检索应答回调（多回调，追加不覆盖）。
// 返回注销函数。
func (r *DeviceSideRole) OnRecordInfo(fn func(RecordInfoFact)) func() {
	r.mu.Lock()
	r.onRecordInfo = append(r.onRecordInfo, fn)
	idx := len(r.onRecordInfo) - 1
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if idx < len(r.onRecordInfo) {
			r.onRecordInfo[idx] = nil
		}
		r.mu.Unlock()
	}
}

// OnInvite INVITE 应答回调（多回调，追加不覆盖）。
func (r *DeviceSideRole) OnInvite(fn func(InviteFact)) {
	r.mu.Lock()
	r.onInvite = append(r.onInvite, fn)
	r.mu.Unlock()
}

// OnPTZ PTZ 控制应答回调（多回调，追加不覆盖）。
func (r *DeviceSideRole) OnPTZ(fn func(PTZFact)) {
	r.mu.Lock()
	r.onPTZ = append(r.onPTZ, fn)
	r.mu.Unlock()
}

// fireRegister 触发所有注册回调（跳过已注销的 nil）。
func (r *DeviceSideRole) fireRegister(f RegisterFact) {
	r.mu.Lock()
	callbacks := make([]func(RegisterFact), 0, len(r.onRegister))
	for _, fn := range r.onRegister {
		if fn != nil {
			callbacks = append(callbacks, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireKeepalive 触发所有心跳回调。
func (r *DeviceSideRole) fireKeepalive(f KeepaliveFact) {
	r.mu.Lock()
	callbacks := make([]func(KeepaliveFact), len(r.onKeepalive))
	copy(callbacks, r.onKeepalive)
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireMessage 触发所有 MESSAGE 回调。
func (r *DeviceSideRole) fireMessage(f MessageFact) {
	r.mu.Lock()
	callbacks := make([]func(MessageFact), len(r.onMessage))
	copy(callbacks, r.onMessage)
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireCatalog 触发所有目录回调（跳过已注销的 nil）。
func (r *DeviceSideRole) fireCatalog(f CatalogFact) {
	r.mu.Lock()
	callbacks := make([]func(CatalogFact), 0, len(r.onCatalog))
	for _, fn := range r.onCatalog {
		if fn != nil {
			callbacks = append(callbacks, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireDeviceInfo 触发所有设备信息回调（跳过已注销的 nil）。
func (r *DeviceSideRole) fireDeviceInfo(f DeviceInfoFact) {
	r.mu.Lock()
	callbacks := make([]func(DeviceInfoFact), 0, len(r.onDeviceInfo))
	for _, fn := range r.onDeviceInfo {
		if fn != nil {
			callbacks = append(callbacks, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireAlarm 触发所有报警回调（跳过已注销的 nil）。
func (r *DeviceSideRole) fireAlarm(f AlarmFact) {
	r.mu.Lock()
	callbacks := make([]func(AlarmFact), 0, len(r.onAlarm))
	for _, fn := range r.onAlarm {
		if fn != nil {
			callbacks = append(callbacks, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireRecordInfo 触发所有录像回调（跳过已注销的 nil）。
func (r *DeviceSideRole) fireRecordInfo(f RecordInfoFact) {
	r.mu.Lock()
	callbacks := make([]func(RecordInfoFact), 0, len(r.onRecordInfo))
	for _, fn := range r.onRecordInfo {
		if fn != nil {
			callbacks = append(callbacks, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// fireInvite 触发所有 INVITE 回调。
func (r *DeviceSideRole) fireInvite(f InviteFact) {
	r.mu.Lock()
	callbacks := make([]func(InviteFact), len(r.onInvite))
	copy(callbacks, r.onInvite)
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// firePTZ 触发所有 PTZ 回调。
func (r *DeviceSideRole) firePTZ(f PTZFact) {
	r.mu.Lock()
	callbacks := make([]func(PTZFact), len(r.onPTZ))
	copy(callbacks, r.onPTZ)
	r.mu.Unlock()
	for _, fn := range callbacks {
		fn(f)
	}
}

// FireInviteFact 触发 INVITE 事实回调（供引擎调用）。
func (r *DeviceSideRole) FireInviteFact(f InviteFact) {
	r.fireInvite(f)
}

// Evidence 返回证据记录器。
func (r *DeviceSideRole) Evidence() *EvidenceRecorder { return r.ev }

// Sessions 返回会话快照。
func (r *DeviceSideRole) Sessions() []RegisterSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RegisterSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, *s)
	}
	return out
}

// Session 返回指定设备会话。
func (r *DeviceSideRole) Session(deviceID string) (RegisterSession, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[deviceID]
	if !ok {
		return RegisterSession{}, false
	}
	return *s, true
}

// ServerID 返回服务器编码。
func (r *DeviceSideRole) ServerID() string { return r.cfg.ServerID }

// LocalPort 返回实际监听端口（UDP）。
func (r *DeviceSideRole) LocalPort() int {
	if r.udp != nil {
		return r.udp.LocalPort()
	}
	return r.cfg.Port
}

// CapturedPackets 返回捕获的报文快照。
func (r *DeviceSideRole) CapturedPackets() []CapturedPacket {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CapturedPacket, len(r.capturedPackets))
	copy(out, r.capturedPackets)
	return out
}

// CaptureOutbound 记录出站报文（供平台发送报文时调用）。
func (r *DeviceSideRole) CaptureOutbound(raw []byte, dst string, proto string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.capturedPackets) < 10000 {
		r.capturedPackets = append(r.capturedPackets, CapturedPacket{
			TS:        time.Now(),
			Direction: "out",
			Src:       fmt.Sprintf("%s:%d", r.cfg.Host, r.LocalPort()),
			Dst:       dst,
			Proto:     proto,
			Raw:       append([]byte(nil), raw...),
		})
	}
}
