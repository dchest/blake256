package blake256

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestBlake256(t *testing.T) {
	var hashes = [][]byte{
		{
			0x0C, 0xE8, 0xD4, 0xEF, 0x4D, 0xD7, 0xCD, 0x8D,
			0x62, 0xDF, 0xDE, 0xD9, 0xD4, 0xED, 0xB0, 0xA7,
			0x74, 0xAE, 0x6A, 0x41, 0x92, 0x9A, 0x74, 0xDA,
			0x23, 0x10, 0x9E, 0x8F, 0x11, 0x13, 0x9C, 0x87,
		},
		{
			0xD4, 0x19, 0xBA, 0xD3, 0x2D, 0x50, 0x4F, 0xB7,
			0xD4, 0x4D, 0x46, 0x0C, 0x42, 0xC5, 0x59, 0x3F,
			0xE5, 0x44, 0xFA, 0x4C, 0x13, 0x5D, 0xEC, 0x31,
			0xE2, 0x1B, 0xD9, 0xAB, 0xDC, 0xC2, 0x2D, 0x41,
		},
	}
	data := make([]byte, 72)

	h := New()
	h.Write(data[:1])
	sum := h.Sum()
	//fmt.Printf("%X\n", sum)
	if !bytes.Equal(hashes[0], sum) {
		t.Errorf("0: expected %X, got %X", hashes[0], sum)
	}

	h.Reset()
	h.Write(data)
	sum = h.Sum()
	//fmt.Printf("%X\n", sum)
	if !bytes.Equal(hashes[1], sum) {
		t.Errorf("1: expected %X, got %X", hashes[1], sum)
	}

}

func BenchmarkLong(b *testing.B) {
	b.StopTimer()
	h := New()
	data := make([]byte, 64)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
		b.SetBytes(64)
	}
}

func BenchmarkShort(b *testing.B) {
	b.StopTimer()
	h := New()
	data := make([]byte, 64)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
		h.Sum()
		h.Reset()
		b.SetBytes(64)
	}
}

func BenchmarkSHA2L(b *testing.B) {
	b.StopTimer()
	h := sha256.New()
	data := make([]byte, 64)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
		b.SetBytes(64)
	}
}

func BenchmarkSHA2S(b *testing.B) {
	b.StopTimer()
	h := sha256.New()
	data := make([]byte, 64)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
		h.Sum()
		h.Reset()
		b.SetBytes(64)
	}
}
