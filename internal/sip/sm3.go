package sip

// SM3 国密哈希（GB/T 32907-2016），纯 Go 实现。
// Go 标准库不含 SM3，此处自实现约百行；测试向量取自标准附录。

// SM3Sum 计算 SM3 摘要，返回 32 字节。
func SM3Sum(data []byte) [32]byte {
	var h [8]uint32
	copyIV(&h)

	// 填充：append 0x80 + 0x00... + 64bit 大端长度
	msg := make([]byte, len(data))
	copy(msg, data)
	bitLen := uint64(len(data)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	for i := 7; i >= 0; i-- {
		msg = append(msg, byte(bitLen>>(8*uint(i))))
	}

	var w [68]uint32
	var w1 [64]uint32
	for off := 0; off < len(msg); off += 64 {
		block := msg[off : off+64]
		for i := 0; i < 16; i++ {
			w[i] = uint32(block[4*i])<<24 | uint32(block[4*i+1])<<16 |
				uint32(block[4*i+2])<<8 | uint32(block[4*i+3])
		}
		for j := 16; j < 68; j++ {
			w[j] = p1(w[j-16]^w[j-9]^rotl(w[j-3], 15)) ^ rotl(w[j-13], 7) ^ w[j-6]
		}
		for j := 0; j < 64; j++ {
			w1[j] = w[j] ^ w[j+4]
		}

		a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		for j := 0; j < 64; j++ {
			ss1 := rotl(rotl(a, 12)+e+rotl(tj(j), uint(j%32)), 7)
			ss2 := ss1 ^ rotl(a, 12)
			tt1 := ff(j, a, b, c) + ss2 + d + w1[j]
			tt2 := gg(j, e, f, g) + ss1 + hh + w[j]
			d = c
			c = rotl(b, 9)
			b = a
			a = tt1
			hh = g
			g = rotl(f, 19)
			f = e
			e = p0(tt2)
		}
		h[0] ^= a
		h[1] ^= b
		h[2] ^= c
		h[3] ^= d
		h[4] ^= e
		h[5] ^= f
		h[6] ^= g
		h[7] ^= hh
	}

	var out [32]byte
	for i := 0; i < 8; i++ {
		out[4*i] = byte(h[i] >> 24)
		out[4*i+1] = byte(h[i] >> 16)
		out[4*i+2] = byte(h[i] >> 8)
		out[4*i+3] = byte(h[i])
	}
	return out
}

// SM3Hex 返回 SM3 摘要的小写十六进制串。
func SM3Hex(data []byte) string {
	sum := SM3Sum(data)
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[2*i] = digits[b>>4]
		out[2*i+1] = digits[b&0x0f]
	}
	return string(out)
}

func copyIV(h *[8]uint32) {
	// 标准初始向量
	h[0], h[1], h[2], h[3] = 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600
	h[4], h[5], h[6], h[7] = 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
}

func tj(j int) uint32 {
	if j < 16 {
		return 0x79cc4519
	}
	return 0x7a879d8a
}

func ff(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func gg(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

func p0(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }

func p1(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

func rotl(x uint32, n uint) uint32 {
	n &= 31
	if n == 0 {
		return x
	}
	return x<<n | x>>(32-n)
}
