package sip

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// RTPPacket 为解析后的 RTP 包。
type RTPPacket struct {
	Version     int
	Padding     bool
	Extension   bool
	CC          int // CSRC count
	Marker      bool
	PayloadType int
	SeqNumber   uint16
	Timestamp   uint32
	SSRC        uint32
	Payload     []byte
	Raw         []byte
	Size        int
}

// RTPStats 为 RTP 流统计分析结果。
type RTPStats struct {
	TotalPackets  int
	TotalBytes    int
	LostPackets   int     // 基于序列号计算的丢包数
	DisorderCount int     // 乱序包数
	DupPackets    int     // 重复序列号
	MaxSeq        uint16  // 最大序列号
	MinSeq        uint16  // 最小序列号
	Duration      float64 // 秒
	AvgPacketRate float64 // 包/秒
	AvgBitRate    float64 // kbps
	SSRC          uint32
	FirstTS       time.Time
	LastTS        time.Time
	SeqSet        map[uint16]bool // 已收到的序列号集合
	mu            sync.Mutex
}

// NewRTPStats 创建 RTP 统计器。
func NewRTPStats() *RTPStats {
	return &RTPStats{SeqSet: map[uint16]bool{}}
}

// Add 接收一个 RTP 包并更新统计。
// 采用 RFC 3550 风格的环形序列号距离计算（int16 环绕），
// 正确处理 65535→0 回绕；乱序迟到包会从丢包计数中回收，
// 避免 UDP 轻微乱序导致丢包率虚高、好摄像头被误判花屏。
func (s *RTPStats) Add(pkt *RTPPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TotalPackets == 0 {
		s.MinSeq = pkt.SeqNumber
		s.MaxSeq = pkt.SeqNumber
		s.FirstTS = time.Now()
		s.SSRC = pkt.SSRC
	} else {
		// 有符号环形距离：+N 表示向前推进 N（含回绕），-N 表示迟到/重复包
		diff := int16(pkt.SeqNumber - s.MaxSeq)
		switch {
		case diff == 0:
			s.DupPackets++
		case diff > 0:
			// 新包（向前推进，含回绕）
			if diff > 1 {
				s.LostPackets += int(diff) - 1
			}
			s.MaxSeq = pkt.SeqNumber
			if pkt.SeqNumber < s.MinSeq {
				s.MinSeq = pkt.SeqNumber
			}
		default: // diff < 0：乱序迟到包或重复包
			if s.SeqSet[pkt.SeqNumber] {
				s.DupPackets++
			} else {
				s.DisorderCount++
				// 此包此前大概率已被计为丢包，回收计数
				if s.LostPackets > 0 {
					s.LostPackets--
				}
			}
		}
	}

	s.SeqSet[pkt.SeqNumber] = true
	s.TotalPackets++
	s.TotalBytes += pkt.Size
	s.LastTS = time.Now()

	if s.TotalPackets > 1 {
		elapsed := s.LastTS.Sub(s.FirstTS).Seconds()
		if elapsed > 0 {
			s.Duration = elapsed
			s.AvgPacketRate = float64(s.TotalPackets) / elapsed
			s.AvgBitRate = float64(s.TotalBytes) * 8 / elapsed / 1000
		}
	}
}

// PacketLossRate 计算丢包率。
func (s *RTPStats) PacketLossRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := s.TotalPackets + s.LostPackets
	if total == 0 {
		return 0
	}
	return float64(s.LostPackets) / float64(total) * 100
}

// RTPReceiver 接收 RTP 媒体流。
type RTPReceiver struct {
	port     int
	conn     *net.UDPConn
	stats    *RTPStats
	stopCh   chan struct{}
	started  bool
	mu       sync.Mutex
	onPacket func(*RTPPacket)
}

// NewRTPReceiver 创建 RTP 接收器。
func NewRTPReceiver(port int) *RTPReceiver {
	return &RTPReceiver{
		port:   port,
		stats:  NewRTPStats(),
		stopCh: make(chan struct{}),
	}
}

// OnPacket 注册包回调。
func (r *RTPReceiver) OnPacket(fn func(*RTPPacket)) { r.onPacket = fn }

// Start 开始接收 RTP 流。
func (r *RTPReceiver) Start() error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", r.port))
	if err != nil {
		r.mu.Unlock()
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.conn = conn
	r.started = true
	r.mu.Unlock()

	go r.readLoop()
	return nil
}

// LocalPort 返回实际监听端口。
func (r *RTPReceiver) LocalPort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		if addr, ok := r.conn.LocalAddr().(*net.UDPAddr); ok {
			return addr.Port
		}
	}
	return r.port
}

func (r *RTPReceiver) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		n, _, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			r.mu.Lock()
			closed := !r.started
			r.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		pkt := ParseRTP(raw)
		if pkt != nil {
			r.stats.Add(pkt)
			if r.onPacket != nil {
				r.onPacket(pkt)
			}
		}
	}
}

// Stop 停止接收。
func (r *RTPReceiver) Stop() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	r.started = false
	close(r.stopCh)
	if r.conn != nil {
		_ = r.conn.Close()
	}
	r.mu.Unlock()
}

// Stats 返回 RTP 统计快照。
func (r *RTPReceiver) Stats() *RTPStats {
	return r.stats
}

// ParseRTP 从原始字节解析 RTP 包。
// 非 RTP 报文（Version != 2，如 STUN/杂包）返回 nil，
// 避免杂包混入统计导致“有流”假象。
func ParseRTP(raw []byte) *RTPPacket {
	if len(raw) < 12 {
		return nil
	}
	if int(raw[0]>>6) != 2 {
		return nil // 仅接受标准 RTP（Version=2）
	}
	pkt := &RTPPacket{
		Raw:         raw,
		Size:        len(raw),
		Version:     int(raw[0] >> 6),
		Padding:     raw[0]&0x20 != 0,
		Extension:   raw[0]&0x10 != 0,
		CC:          int(raw[0] & 0x0f),
		Marker:      raw[1]&0x80 != 0,
		PayloadType: int(raw[1] & 0x7f),
		SeqNumber:   binary.BigEndian.Uint16(raw[2:4]),
		Timestamp:   binary.BigEndian.Uint32(raw[4:8]),
		SSRC:        binary.BigEndian.Uint32(raw[8:12]),
	}
	headerLen := 12 + pkt.CC*4
	if pkt.Extension {
		if len(raw) < headerLen+4 {
			return pkt
		}
		extLen := int(binary.BigEndian.Uint16(raw[headerLen+2:headerLen+4])) * 4
		headerLen += 4 + extLen
	}
	if headerLen > len(raw) {
		return pkt
	}
	if pkt.Padding && len(raw) > 0 {
		padLen := int(raw[len(raw)-1])
		if padLen <= len(raw)-headerLen {
			pkt.Payload = raw[headerLen : len(raw)-padLen]
		} else {
			pkt.Payload = raw[headerLen:]
		}
	} else {
		pkt.Payload = raw[headerLen:]
	}
	return pkt
}

// RTPStreamAnalysis 为 RTP 流分析结论。
type RTPStreamAnalysis struct {
	Stats           *RTPStats
	LossRate        float64 // 丢包率 %
	IsScreenCorrupt bool    // 花屏推定（丢包率>5%）
	IsStuttering    bool    // 卡顿推定（包率极不稳定）
	BitRateOK       bool    // 码率在合理范围
	Conclusions     []string
}

// AnalyzeRTPStream 对已收到的 RTP 统计进行分析。
func AnalyzeRTPStream(stats *RTPStats) RTPStreamAnalysis {
	a := RTPStreamAnalysis{Stats: stats}
	lossRate := stats.PacketLossRate()
	a.LossRate = lossRate
	a.BitRateOK = stats.AvgBitRate > 64 // 至少 64kbps

	if lossRate > 5 {
		a.IsScreenCorrupt = true
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("丢包率 %.1f%% 超过 5%%，可能导致花屏/马赛克", lossRate))
	} else if lossRate > 1 {
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("丢包率 %.1f%%，轻微丢包", lossRate))
	} else {
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("丢包率 %.1f%%，正常", lossRate))
	}

	if stats.TotalPackets > 0 && stats.AvgPacketRate > 0 {
		if stats.AvgPacketRate < 10 {
			a.IsStuttering = true
			a.Conclusions = append(a.Conclusions, fmt.Sprintf("包率 %.0f/s 偏低，可能卡顿", stats.AvgPacketRate))
		}
	}

	if stats.DupPackets > 0 {
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("检测到 %d 个重复包", stats.DupPackets))
	}

	if stats.DisorderCount > 0 {
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("检测到 %d 个乱序包", stats.DisorderCount))
	}

	if stats.SSRC != 0 {
		a.Conclusions = append(a.Conclusions, fmt.Sprintf("SSRC=0x%08X", stats.SSRC))
	}

	return a
}

// RTPToText 将 RTP 分析结果格式化为人话文本。
func RTPToText(a RTPStreamAnalysis) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("RTP 流分析：\n"))
	b.WriteString(fmt.Sprintf("  总包数: %d, 总字节: %d\n", a.Stats.TotalPackets, a.Stats.TotalBytes))
	b.WriteString(fmt.Sprintf("  持续时间: %.1fs\n", a.Stats.Duration))
	b.WriteString(fmt.Sprintf("  丢包: %d (%.1f%%)\n", a.Stats.LostPackets, a.LossRate))
	b.WriteString(fmt.Sprintf("  平均码率: %.0f kbps\n", a.Stats.AvgBitRate))
	if a.IsScreenCorrupt {
		b.WriteString("  ⚠️ 丢包率过高，可能导致花屏/马赛克\n")
	}
	if a.IsStuttering {
		b.WriteString("  ⚠️ 包率偏低，可能卡顿\n")
	}
	for _, c := range a.Conclusions {
		b.WriteString("  • " + c + "\n")
	}
	return b.String()
}
