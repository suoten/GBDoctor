package sip

import (
	"encoding/binary"
	"testing"
)

// makeRTP 构造一个最小 RTP 包。
func makeRTP(seq uint16, ts uint32, ssrc uint32, payload []byte) []byte {
	buf := make([]byte, 12+len(payload))
	buf[0] = 0x80 // V=2, no padding/extension/CC
	buf[1] = 0x60 // M=0, PT=96
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	copy(buf[12:], payload)
	return buf
}

func TestParseRTP(t *testing.T) {
	raw := makeRTP(100, 90000, 0x12345678, []byte{0x01, 0x02, 0x03})
	pkt := ParseRTP(raw)
	if pkt == nil {
		t.Fatal("ParseRTP 返回 nil")
	}
	if pkt.Version != 2 {
		t.Errorf("Version = %d, want 2", pkt.Version)
	}
	if pkt.PayloadType != 96 {
		t.Errorf("PayloadType = %d, want 96", pkt.PayloadType)
	}
	if pkt.SeqNumber != 100 {
		t.Errorf("SeqNumber = %d, want 100", pkt.SeqNumber)
	}
	if pkt.Timestamp != 90000 {
		t.Errorf("Timestamp = %d, want 90000", pkt.Timestamp)
	}
	if pkt.SSRC != 0x12345678 {
		t.Errorf("SSRC = 0x%08X, want 0x12345678", pkt.SSRC)
	}
	if len(pkt.Payload) != 3 {
		t.Errorf("Payload len = %d, want 3", len(pkt.Payload))
	}
	if pkt.Size != len(raw) {
		t.Errorf("Size = %d, want %d", pkt.Size, len(raw))
	}
}

func TestParseRTPTooShort(t *testing.T) {
	if ParseRTP([]byte{0x80, 0x60}) != nil {
		t.Error("短包应返回 nil")
	}
}

func TestRTPStatsNoLoss(t *testing.T) {
	stats := NewRTPStats()
	for i := 0; i < 100; i++ {
		pkt := &RTPPacket{SeqNumber: uint16(i), Size: 100}
		stats.Add(pkt)
	}
	if stats.LostPackets != 0 {
		t.Errorf("LostPackets = %d, want 0", stats.LostPackets)
	}
	if stats.TotalPackets != 100 {
		t.Errorf("TotalPackets = %d, want 100", stats.TotalPackets)
	}
	rate := stats.PacketLossRate()
	if rate != 0 {
		t.Errorf("PacketLossRate = %.1f, want 0", rate)
	}
}

func TestRTPStatsWithLoss(t *testing.T) {
	stats := NewRTPStats()
	// 发送 seq 0,1,2, 跳过 3,4, 发送 5
	for _, seq := range []uint16{0, 1, 2, 5} {
		pkt := &RTPPacket{SeqNumber: seq, Size: 100}
		stats.Add(pkt)
	}
	if stats.LostPackets != 2 {
		t.Errorf("LostPackets = %d, want 2", stats.LostPackets)
	}
}

func TestRTPStatsDuplicate(t *testing.T) {
	stats := NewRTPStats()
	for _, seq := range []uint16{0, 0, 1, 1, 2} {
		pkt := &RTPPacket{SeqNumber: seq, Size: 100}
		stats.Add(pkt)
	}
	if stats.DupPackets != 2 {
		t.Errorf("DupPackets = %d, want 2", stats.DupPackets)
	}
}

func TestAnalyzeRTPStreamNormal(t *testing.T) {
	stats := NewRTPStats()
	for i := 0; i < 100; i++ {
		pkt := &RTPPacket{SeqNumber: uint16(i), Size: 1000}
		stats.Add(pkt)
	}
	a := AnalyzeRTPStream(stats)
	if a.IsScreenCorrupt {
		t.Error("正常流不应判定花屏")
	}
	if a.IsStuttering {
		t.Error("正常流不应判定卡顿")
	}
}

func TestAnalyzeRTPStreamHighLoss(t *testing.T) {
	stats := NewRTPStats()
	// 发送 100 个包，但有 10 个间隔（模拟 10% 丢包）
	for i := 0; i < 100; i++ {
		seq := uint16(i * 2) // 0,2,4,6...  每个之间跳过一个
		pkt := &RTPPacket{SeqNumber: seq, Size: 1000}
		stats.Add(pkt)
	}
	a := AnalyzeRTPStream(stats)
	if !a.IsScreenCorrupt {
		t.Error("高丢包率应判定花屏")
	}
	if a.LossRate <= 5 {
		t.Errorf("LossRate = %.1f, should > 5%%", a.LossRate)
	}
}

func TestRTPToText(t *testing.T) {
	stats := NewRTPStats()
	stats.Add(&RTPPacket{SeqNumber: 0, Size: 100})
	stats.Add(&RTPPacket{SeqNumber: 1, Size: 100})
	a := AnalyzeRTPStream(stats)
	text := RTPToText(a)
	if text == "" {
		t.Error("RTPToText 不应为空")
	}
	if !contains(text, "RTP") {
		t.Error("RTPToText 应包含 RTP")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
