// Package blake256 implements BLAKE-256 hash function (SHA-3
// candidate).
//
// Derived from blake256_light.c: light portable C implementation of
// BLAKE-256 (http://www.131002.net/blake/#sw)
package blake256

import (
	"os"
	"hash"
)

// The size of the checksum in bytes.
const Size = 32

// The block size of the hash algorithm in bytes.
const BlockSize = 64

type digest struct {
	h      [8]uint32
	s      [4]uint32
	t      [2]uint32
	nullt  int
	buf    [BlockSize]uint8
	buflen int // buffer length in bits
}

var sigma = [][]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}}

var cst = [16]uint32{
	0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
	0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
	0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
	0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917}

var padding = []uint8{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0}

func rot(x, n uint32) uint32 {
	return x<<(32-n) | x>>n
}

func u8to32(p []byte) uint32 {
	return uint32(p[0])<<24 | uint32(p[1])<<16 |
		uint32(p[2])<<8 | uint32(p[3])
}

func u32to8(p []byte, v uint32) {
	p[0] = byte(v >> 24)
	p[1] = byte(v >> 16)
	p[2] = byte(v >> 8)
	p[3] = byte(v)
}

func (d *digest) _Block(block []uint8) {
	var m [16]uint32

	for i := 0; i < 16; i++ {
		m[i] = u8to32(block[i*4:])
	}

	v0 := d.h[0]
	v1 := d.h[1]
	v2 := d.h[2]
	v3 := d.h[3]
	v4 := d.h[4]
	v5 := d.h[5]
	v6 := d.h[6]
	v7 := d.h[7]
	v8 := d.s[0] ^ 0x243F6A88
	v9 := d.s[1] ^ 0x85A308D3
	v10 := d.s[2] ^ 0x13198A2E
	v11 := d.s[3] ^ 0x03707344
	v12 := uint32(0xA4093822)
	v13 := uint32(0x299F31D0)
	v14 := uint32(0x082EFA98)
	v15 := uint32(0xEC4E6C89)
	if d.nullt == 0 {
		v12 ^= d.t[0]
		v13 ^= d.t[0]
		v14 ^= d.t[1]
		v15 ^= d.t[1]
	}

	for i := 0; i < 14; i++ {
		si := sigma[i]
		v0 += (m[si[0]] ^ cst[si[0+1]]) + v4
		v12 = (v12^v0)<<(32-16) | (v12^v0)>>16
		v8 += v12
		v4 = (v4^v8)<<(32-12) | (v4^v8)>>12
		v0 += (m[si[0+1]] ^ cst[si[0]]) + v4
		v12 = (v12^v0)<<(32-8) | (v12^v0)>>8
		v8 += v12
		v4 = (v4^v8)<<(32-7) | (v4^v8)>>7
		v1 += (m[si[2]] ^ cst[si[2+1]]) + v5
		v13 = (v13^v1)<<(32-16) | (v13^v1)>>16
		v9 += v13
		v5 = (v5^v9)<<(32-12) | (v5^v9)>>12
		v1 += (m[si[2+1]] ^ cst[si[2]]) + v5
		v13 = (v13^v1)<<(32-8) | (v13^v1)>>8
		v9 += v13
		v5 = (v5^v9)<<(32-7) | (v5^v9)>>7
		v2 += (m[si[4]] ^ cst[si[4+1]]) + v6
		v14 = (v14^v2)<<(32-16) | (v14^v2)>>16
		v10 += v14
		v6 = (v6^v10)<<(32-12) | (v6^v10)>>12
		v2 += (m[si[4+1]] ^ cst[si[4]]) + v6
		v14 = (v14^v2)<<(32-8) | (v14^v2)>>8
		v10 += v14
		v6 = (v6^v10)<<(32-7) | (v6^v10)>>7
		v3 += (m[si[6]] ^ cst[si[6+1]]) + v7
		v15 = (v15^v3)<<(32-16) | (v15^v3)>>16
		v11 += v15
		v7 = (v7^v11)<<(32-12) | (v7^v11)>>12
		v3 += (m[si[6+1]] ^ cst[si[6]]) + v7
		v15 = (v15^v3)<<(32-8) | (v15^v3)>>8
		v11 += v15
		v7 = (v7^v11)<<(32-7) | (v7^v11)>>7
		v3 += (m[si[14]] ^ cst[si[14+1]]) + v4
		v14 = (v14^v3)<<(32-16) | (v14^v3)>>16
		v9 += v14
		v4 = (v4^v9)<<(32-12) | (v4^v9)>>12
		v3 += (m[si[14+1]] ^ cst[si[14]]) + v4
		v14 = (v14^v3)<<(32-8) | (v14^v3)>>8
		v9 += v14
		v4 = (v4^v9)<<(32-7) | (v4^v9)>>7
		v2 += (m[si[12]] ^ cst[si[12+1]]) + v7
		v13 = (v13^v2)<<(32-16) | (v13^v2)>>16
		v8 += v13
		v7 = (v7^v8)<<(32-12) | (v7^v8)>>12
		v2 += (m[si[12+1]] ^ cst[si[12]]) + v7
		v13 = (v13^v2)<<(32-8) | (v13^v2)>>8
		v8 += v13
		v7 = (v7^v8)<<(32-7) | (v7^v8)>>7
		v0 += (m[si[8]] ^ cst[si[8+1]]) + v5
		v15 = (v15^v0)<<(32-16) | (v15^v0)>>16
		v10 += v15
		v5 = (v5^v10)<<(32-12) | (v5^v10)>>12
		v0 += (m[si[8+1]] ^ cst[si[8]]) + v5
		v15 = (v15^v0)<<(32-8) | (v15^v0)>>8
		v10 += v15
		v5 = (v5^v10)<<(32-7) | (v5^v10)>>7
		v1 += (m[si[10]] ^ cst[si[10+1]]) + v6
		v12 = (v12^v1)<<(32-16) | (v12^v1)>>16
		v11 += v12
		v6 = (v6^v11)<<(32-12) | (v6^v11)>>12
		v1 += (m[si[10+1]] ^ cst[si[10]]) + v6
		v12 = (v12^v1)<<(32-8) | (v12^v1)>>8
		v11 += v12
		v6 = (v6^v11)<<(32-7) | (v6^v11)>>7
	}

	d.h[0] ^= v0 ^ v8 ^ d.s[0]
	d.h[1] ^= v1 ^ v9 ^ d.s[1]
	d.h[2] ^= v2 ^ v10 ^ d.s[2]
	d.h[3] ^= v3 ^ v11 ^ d.s[3]
	d.h[4] ^= v4 ^ v12 ^ d.s[0]
	d.h[5] ^= v5 ^ v13 ^ d.s[1]
	d.h[6] ^= v6 ^ v14 ^ d.s[2]
	d.h[7] ^= v7 ^ v15 ^ d.s[3]
}

func (d *digest) Reset() {
	d.h[0] = 0x6A09E667
	d.h[1] = 0xBB67AE85
	d.h[2] = 0x3C6EF372
	d.h[3] = 0xA54FF53A
	d.h[4] = 0x510E527F
	d.h[5] = 0x9B05688C
	d.h[6] = 0x1F83D9AB
	d.h[7] = 0x5BE0CD19
	d.t[0] = 0
	d.t[1] = 0
	d.nullt = 0
	d.s[0] = 0
	d.s[1] = 0
	d.s[2] = 0
	d.s[3] = 0
	d.buflen = 0
}

func (d *digest) Size() int { return Size }

// update updates the internal state of digest with the given data of
// datalen in bits (not bytes!).
func (d *digest) update(data []byte, datalen int) {
	left := d.buflen >> 3
	fill := 64 - left

	if left != 0 && (datalen>>3)&0x3F >= fill {
		copy(d.buf[left:], data[:fill])
		d.t[0] += 512
		if d.t[0] == 0 {
			d.t[1]++
		}
		d._Block(d.buf[:])
		data = data[fill:]
		datalen -= fill << 3
		left = 0
	}

	for datalen >= 512 {
		d.t[0] += 512
		if d.t[0] == 0 {
			d.t[1]++
		}
		d._Block(data)
		data = data[64:]
		datalen -= 512
	}

	if datalen > 0 {
		copy(d.buf[left:], data)
		d.buflen = left<<3 + datalen
	} else {
		d.buflen = 0
	}
}

func (d *digest) Write(p []byte) (nn int, err os.Error) {
	d.update(p, len(p)*8)
	return len(p), nil
}

func (d *digest) Sum() []byte {
	ubuflen := uint32(d.buflen)
	msglen := make([]byte, 8)
	zo := []byte{0x01}
	oo := []byte{0x81}
	lo := d.t[0] + ubuflen
	hi := d.t[1]
	if lo < ubuflen {
		hi++
	}
	u32to8(msglen, hi)
	u32to8(msglen[4:], lo)

	if d.buflen == 440 { // one padding byte
		d.t[0] -= 8
		d.update(oo, 8)
	} else {
		if d.buflen < 440 { // enought space to fill the block
			if d.buflen == 0 {
				d.nullt = 1
			}
			d.t[0] -= 440 - ubuflen
			d.update(padding, 440-d.buflen)
		} else { // need 2 compressions
			d.t[0] -= 512 - ubuflen
			d.update(padding, 512-d.buflen)
			d.t[0] -= 440
			d.update(padding[1:], 440)
			d.nullt = 1
		}
		d.update(zo, 8)
		d.t[0] -= 8
	}
	d.t[0] -= 64
	d.update(msglen, 64)

	out := make([]byte, 32)
	u32to8(out[0:], d.h[0])
	u32to8(out[4:], d.h[1])
	u32to8(out[8:], d.h[2])
	u32to8(out[12:], d.h[3])
	u32to8(out[16:], d.h[4])
	u32to8(out[20:], d.h[5])
	u32to8(out[24:], d.h[6])
	u32to8(out[28:], d.h[7])
	return out
}

func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}
