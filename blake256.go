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
	hashSize int              // hash output size in bits (224 or 256)
	h        [8]uint32        // current chain value
	salt     [4]uint32        // salt (zero by default)
	t        [2]uint32        // counter of hashed bits
	nullt    bool             // special case for finalization
	buf      [BlockSize]uint8 // cache for data not yet compressed
	buflen   int              // cache length in bits
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

func (d *digest) _Block(p []uint8) {
	var m [16]uint32
	for i := 0; i < 16; i++ {
		j := i * 4
		m[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
	}
	v0 := d.h[0]
	v1 := d.h[1]
	v2 := d.h[2]
	v3 := d.h[3]
	v4 := d.h[4]
	v5 := d.h[5]
	v6 := d.h[6]
	v7 := d.h[7]
	v8 := d.salt[0] ^ cst[0]
	v9 := d.salt[1] ^ cst[1]
	v10 := d.salt[2] ^ cst[2]
	v11 := d.salt[3] ^ cst[3]
	v12 := cst[4]
	v13 := cst[5]
	v14 := cst[6]
	v15 := cst[7]
	if !d.nullt {
		v12 ^= d.t[0]
		v13 ^= d.t[0]
		v14 ^= d.t[1]
		v15 ^= d.t[1]
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

	d.h[0] ^= v0 ^ v8 ^ d.salt[0]
	d.h[1] ^= v1 ^ v9 ^ d.salt[1]
	d.h[2] ^= v2 ^ v10 ^ d.salt[2]
	d.h[3] ^= v3 ^ v11 ^ d.salt[3]
	d.h[4] ^= v4 ^ v12 ^ d.salt[0]
	d.h[5] ^= v5 ^ v13 ^ d.salt[1]
	d.h[6] ^= v6 ^ v14 ^ d.salt[2]
	d.h[7] ^= v7 ^ v15 ^ d.salt[3]
}

// Reset resets the state of digest. It leaves salt intact.
func (d *digest) Reset() {
	if d.hashSize == 224 {
		d.h = iv224
	} else {
		d.h = iv256
	}
	d.t[0] = 0
	d.t[1] = 0
	d.nullt = false
	d.buflen = 0
}

func (d *digest) Size() int { return d.hashSize >> 3 }

func (d *digest) BlockSize() int { return BlockSize }

// update updates the internal state of digest with the given data,
// of the given length in bits (!).
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
		d._Block(data[:64])
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

func (d *digest) Write(p []byte) (nn int, err error) {
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
func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	ubuflen := uint32(d.buflen)
	lo := d.t[0] + ubuflen
	hi := d.t[1]
	if lo < ubuflen {
		hi++
	}
	msglen := make([]byte, 8)
	u32to8(msglen[0:4], hi)
	u32to8(msglen[4:8], lo)

	if d.buflen == 440 { // one padding byte
		d.t[0] -= 8
		if d.hashSize == 224 {
			d.update([]byte{0x80}, 8)
		} else {
			d.update([]byte{0x81}, 8)
		}
	} else {
		pad := [64]byte{0x80}
		if d.buflen < 440 { // enough space to fill the block
			if d.buflen == 0 {
				d.nullt = true
			}
			d.t[0] -= 440 - ubuflen
			d.update(pad[:], uint64(440-d.buflen))
		} else { // need 2 compressions
			d.t[0] -= 512 - ubuflen
			d.update(pad[:], uint64(512-d.buflen))
			d.t[0] -= 440
			d.update(pad[1:], 440)
			d.nullt = true
		}
		if d.hashSize == 224 {
			d.update([]byte{0x00}, 8)
		} else {
			d.update([]byte{0x01}, 8)
		}
		d.t[0] -= 8
	}
	d.t[0] -= 64
	d.update(msglen, 64)

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
	d.salt[0] = uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
	d.salt[1] = uint32(s[4])<<24 | uint32(s[5])<<16 | uint32(s[6])<<8 | uint32(s[7])
	d.salt[2] = uint32(s[8])<<24 | uint32(s[9])<<16 | uint32(s[10])<<8 | uint32(s[11])
	d.salt[3] = uint32(s[12])<<24 | uint32(s[13])<<16 | uint32(s[14])<<8 | uint32(s[15])
}

func newDigest(bitSize int) (d *digest) {
	d = new(digest)
	d.hashSize = bitSize
	d.Reset()
	return
}

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
	return newDigest(256)
}

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
	return newDigest(224)
}

// NewSalt is like New but initializes salt with the given 16-byte slice.
func NewSalt(salt []byte) hash.Hash {
	d := newDigest(256)
	d.setSalt(salt)
	return d
}

// New224Salt is like New224 but initializes salt with the given 16-byte slice.
func New224Salt(salt []byte) hash.Hash {
	d := newDigest(224)
	d.setSalt(salt)
	return d
}
