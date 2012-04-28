// Written by Dmitry Chestnykh. Put into the public domain.

// Package blake256 implements BLAKE-256 and BLAKE-224 hash functions (SHA-3
// candidate).
//
// Derived from reference implementation in C.
package blake256

import "hash"

// The block size of the hash algorithm in bytes.
const BlockSize = 64

type digest struct {
	hashSize int             // hash output size in bits (224 or 256)
	h        [8]uint32       // current chain value
	s        [4]uint32       // salt (zero by default)
	t        uint64          // message length counter in bits
	nullt    bool            // special case for finalization: skip counter
	x        [BlockSize]byte // buffer for data not yet compressed
	nx       int             // number of bytes in buffer
}

var (
	// Permutations of {0, ..., 15}.
	sigma = [14][16]uint8{
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

	// Constants.
	cst = [16]uint32{
		0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
		0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
		0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
		0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917}

	// Initialization values.
	iv256 = [8]uint32{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

	iv224 = [8]uint32{
		0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
		0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4}
)

func _Block(d *digest, p []uint8) int {
	var m [16]uint32
	n := 0
	h0, h1, h2, h3, h4, h5, h6, h7 := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

	for len(p) >= BlockSize {
		v0, v1, v2, v3, v4, v5, v6, v7 := h0, h1, h2, h3, h4, h5, h6, h7
		v8 := cst[0] ^ d.s[0]
		v9 := cst[1] ^ d.s[1]
		v10 := cst[2] ^ d.s[2]
		v11 := cst[3] ^ d.s[3]
		v12 := cst[4]
		v13 := cst[5]
		v14 := cst[6]
		v15 := cst[7]
		d.t += 512
		if !d.nullt {
			v12 ^= uint32(d.t)
			v13 ^= uint32(d.t)
			v14 ^= uint32(d.t >> 32)
			v15 ^= uint32(d.t >> 32)
		}

		for i := 0; i < 16; i++ {
			j := i * 4
			m[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		for i := 0; i < 14; i++ {
			si := &sigma[i]
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
		h0 ^= v0 ^ v8 ^ d.s[0]
		h1 ^= v1 ^ v9 ^ d.s[1]
		h2 ^= v2 ^ v10 ^ d.s[2]
		h3 ^= v3 ^ v11 ^ d.s[3]
		h4 ^= v4 ^ v12 ^ d.s[0]
		h5 ^= v5 ^ v13 ^ d.s[1]
		h6 ^= v6 ^ v14 ^ d.s[2]
		h7 ^= v7 ^ v15 ^ d.s[3]

		p = p[BlockSize:]
		n += BlockSize
	}
	d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
	return n
}

// Reset resets the state of digest. It leaves salt intact.
func (d *digest) Reset() {
	if d.hashSize == 224 {
		d.h = iv224
	} else {
		d.h = iv256
	}
	d.t = 0
	d.nx = 0
	d.nullt = false
}

func (d *digest) Size() int { return d.hashSize >> 3 }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := len(p)
		if n > BlockSize-d.nx {
			n = BlockSize - d.nx
		}
		d.nx += copy(d.x[d.nx:], p)
		if d.nx == BlockSize {
			_Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum returns the calculated checksum.
func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	nx := uint64(d.nx)
	l := d.t + nx<<3
	len := make([]byte, 8)
	len[0] = byte(l >> 56)
	len[1] = byte(l >> 48)
	len[2] = byte(l >> 40)
	len[3] = byte(l >> 32)
	len[4] = byte(l >> 24)
	len[5] = byte(l >> 16)
	len[6] = byte(l >> 8)
	len[7] = byte(l)

	if nx == 55 {
		// One padding byte.
		d.t -= 8
		if d.hashSize == 224 {
			d.Write([]byte{0x80})
		} else {
			d.Write([]byte{0x81})
		}
	} else {
		pad := [64]byte{0x80}
		if nx < 55 {
			// Enough space to fill the block.
			if nx == 0 {
				d.nullt = true
			}
			d.t -= 440 - nx<<3
			d.Write(pad[0 : 55-nx])
		} else {
			// Need 2 compressions.
			d.t -= 512 - nx<<3
			d.Write(pad[0 : 64-nx])
			d.t -= 440
			d.Write(pad[1:56])
			d.nullt = true
		}
		if d.hashSize == 224 {
			d.Write([]byte{0x00})
		} else {
			d.Write([]byte{0x01})
		}
		d.t -= 8
	}
	d.t -= 64
	d.Write(len)

	out := make([]byte, d.Size())
	j := 0
	for _, s := range d.h[:d.hashSize>>5] {
		out[j+0] = byte(s >> 24)
		out[j+1] = byte(s >> 16)
		out[j+2] = byte(s >> 8)
		out[j+3] = byte(s >> 0)
		j += 4
	}
	return append(in, out...)
}

func (d *digest) setSalt(s []byte) {
	if len(s) != 16 {
		panic("salt length must be 16 bytes")
	}
	d.s[0] = uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
	d.s[1] = uint32(s[4])<<24 | uint32(s[5])<<16 | uint32(s[6])<<8 | uint32(s[7])
	d.s[2] = uint32(s[8])<<24 | uint32(s[9])<<16 | uint32(s[10])<<8 | uint32(s[11])
	d.s[3] = uint32(s[12])<<24 | uint32(s[13])<<16 | uint32(s[14])<<8 | uint32(s[15])
}

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
	return &digest{
		hashSize: 256,
		h: iv256,
	}
}

// NewSalt is like New but initializes salt with the given 16-byte slice.
func NewSalt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 256,
		h: iv256,
	}
	d.setSalt(salt)
	return d
}

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
	return &digest{
		hashSize: 224,
		h: iv224,
	}
}

// New224Salt is like New224 but initializes salt with the given 16-byte slice.
func New224Salt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 224,
		h: iv224,
	}
	d.setSalt(salt)
	return d
}
