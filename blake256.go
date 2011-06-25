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
	salt   [4]uint32
	t      [2]uint32
	nullt  bool
	buf    [BlockSize]uint8
	buflen int  // buffer length in bits
}

var sigma = [...][...]uint8{
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

func (d *digest) _Block(p []uint8) {
	m := [16]uint32{
		uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3]),
		uint32(p[4])<<24 | uint32(p[5])<<16 | uint32(p[6])<<8 | uint32(p[7]),
		uint32(p[8])<<24 | uint32(p[9])<<16 | uint32(p[10])<<8 | uint32(p[11]),
		uint32(p[12])<<24 | uint32(p[13])<<16 | uint32(p[14])<<8 | uint32(p[15]),
		uint32(p[16])<<24 | uint32(p[17])<<16 | uint32(p[18])<<8 | uint32(p[19]),
		uint32(p[20])<<24 | uint32(p[21])<<16 | uint32(p[22])<<8 | uint32(p[23]),
		uint32(p[24])<<24 | uint32(p[25])<<16 | uint32(p[26])<<8 | uint32(p[27]),
		uint32(p[28])<<24 | uint32(p[29])<<16 | uint32(p[30])<<8 | uint32(p[31]),
		uint32(p[32])<<24 | uint32(p[33])<<16 | uint32(p[34])<<8 | uint32(p[35]),
		uint32(p[36])<<24 | uint32(p[37])<<16 | uint32(p[38])<<8 | uint32(p[39]),
		uint32(p[40])<<24 | uint32(p[41])<<16 | uint32(p[42])<<8 | uint32(p[43]),
		uint32(p[44])<<24 | uint32(p[45])<<16 | uint32(p[46])<<8 | uint32(p[47]),
		uint32(p[48])<<24 | uint32(p[49])<<16 | uint32(p[50])<<8 | uint32(p[51]),
		uint32(p[52])<<24 | uint32(p[53])<<16 | uint32(p[54])<<8 | uint32(p[55]),
		uint32(p[56])<<24 | uint32(p[57])<<16 | uint32(p[58])<<8 | uint32(p[59]),
		uint32(p[60])<<24 | uint32(p[61])<<16 | uint32(p[62])<<8 | uint32(p[63]),
	}
	v0 := d.h[0]
	v1 := d.h[1]
	v2 := d.h[2]
	v3 := d.h[3]
	v4 := d.h[4]
	v5 := d.h[5]
	v6 := d.h[6]
	v7 := d.h[7]
	v8 := d.salt[0] ^ 0x243F6A88
	v9 := d.salt[1] ^ 0x85A308D3
	v10 := d.salt[2] ^ 0x13198A2E
	v11 := d.salt[3] ^ 0x03707344
	v12 := uint32(0xA4093822)
	v13 := uint32(0x299F31D0)
	v14 := uint32(0x082EFA98)
	v15 := uint32(0xEC4E6C89)
	if !d.nullt {
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

	d.h[0] ^= v0 ^ v8 ^ d.salt[0]
	d.h[1] ^= v1 ^ v9 ^ d.salt[1]
	d.h[2] ^= v2 ^ v10 ^ d.salt[2]
	d.h[3] ^= v3 ^ v11 ^ d.salt[3]
	d.h[4] ^= v4 ^ v12 ^ d.salt[0]
	d.h[5] ^= v5 ^ v13 ^ d.salt[1]
	d.h[6] ^= v6 ^ v14 ^ d.salt[2]
	d.h[7] ^= v7 ^ v15 ^ d.salt[3]
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
	d.nullt = false
	d.salt[0] = 0
	d.salt[1] = 0
	d.salt[2] = 0
	d.salt[3] = 0
	d.buflen = 0
}

func (d *digest) Size() int { return Size }

// update updates the internal state of digest with the given data of
// datalen in bits (not bytes!).
func (d *digest) update(data []byte, datalen uint64) {
	left := d.buflen >> 3
	fill := 64 - left

	if left != 0 && int(datalen>>3)&0x3F >= fill {
		copy(d.buf[left:], data[:fill])
		d.t[0] += 512
		if d.t[0] == 0 {
			d.t[1]++
		}
		d._Block(d.buf[:])
		data = data[fill:]
		datalen -= uint64(fill) << 3
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
		d.buflen = left<<3 + int(datalen)
	} else {
		d.buflen = 0
	}
}

func (d *digest) Write(p []byte) (nn int, err os.Error) {
	nn = len(p)
	d.update(p, uint64(nn)*8)
	return
}

func u32to8(p []byte, v uint32) {
	p[0] = byte(v >> 24)
	p[1] = byte(v >> 16)
	p[2] = byte(v >> 8)
	p[3] = byte(v)
}

// Sum returns the calculated checksum.
func (d0 *digest) Sum() []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := new(digest)
	*d = *d0

	ubuflen := uint32(d.buflen)
	lo := d.t[0] + ubuflen
	hi := d.t[1]
	if lo < ubuflen {
		hi++
	}
	msglen := make([]byte, 8)
	u32to8(msglen, hi)
	u32to8(msglen[4:], lo)

	if d.buflen == 440 { // one padding byte
		d.t[0] -= 8
		d.update([]byte{0x81}, 8)
	} else {
		if d.buflen < 440 { // enought space to fill the block
			if d.buflen == 0 {
				d.nullt = true
			}
			d.t[0] -= 440 - ubuflen
			d.update(padding, uint64(440-d.buflen))
		} else { // need 2 compressions
			d.t[0] -= 512 - ubuflen
			d.update(padding, uint64(512-d.buflen))
			d.t[0] -= 440
			d.update(padding[1:], 440)
			d.nullt = true
		}
		d.update([]byte{0x01}, 8)
		d.t[0] -= 8
	}
	d.t[0] -= 64
	d.update(msglen, 64)

	out := make([]byte, 32)
	j := 0
	for _, s := range d.h {
		out[j+0] = byte(s >> 24)
		out[j+1] = byte(s >> 16)
		out[j+2] = byte(s >> 8)
		out[j+3] = byte(s >> 0)
		j += 4
	}
	return out
}

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}
