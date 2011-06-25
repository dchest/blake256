package blake256

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"
)

func TestBlake256(t *testing.T) {
	// Test as in C program.
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

	// Try to continue hashing.
	h.Write(data[1:])
	sum = h.Sum()
	//fmt.Printf("%X\n", sum)
	if !bytes.Equal(hashes[1], sum) {
		t.Errorf("1(1): expected %X, got %X", hashes[1], sum)
	}

	// Try with reset.
	h.Reset()
	h.Write(data)
	sum = h.Sum()
	//fmt.Printf("%X\n", sum)
	if !bytes.Equal(hashes[1], sum) {
		t.Errorf("1(2): expected %X, got %X", hashes[1], sum)
	}

	// Other test vectors.
	vectors := []struct{ out, in string }{
		{"7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
		"The quick brown fox jumps over the lazy dog"},
		{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
		"BLAKE"},
		{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
		""},
		{"18a393b4e62b1887a2edf79a5c5a5464daf5bbb976f4007bea16a73e4c1e198e",
		"'BLAKE wins SHA-3! Hooray!!!' (I have time machine)"},
		{"fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2",
		"Go"},
		{"1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711",
		"HELP! I'm trapped in hash!"},
	}
	for i, v := range vectors {
		h := New()
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum())
		if res != v.out {
			t.Errorf("[v] %d: expected %q, got %q", i, v.out, res)
		}
	}
}

var longData, shortData []byte

func init() {
	longData = make([]byte, 4096)
	shortData = make([]byte, 64)
}

func testHash(b *testing.B, hashfunc func() hash.Hash, data []byte) {
	b.StopTimer()
	h := hashfunc()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
		h.Sum()
		h.Reset()
		b.SetBytes(int64(len(data)))
	}
}

func BenchmarkLong(b *testing.B) {
	testHash(b, New, longData)
}

func BenchmarkShort(b *testing.B) {
	testHash(b, New, shortData)
}

func BenchmarkSHA2L(b *testing.B) {
	testHash(b, sha256.New, longData)
}

func BenchmarkSHA2S(b *testing.B) {
	testHash(b, sha256.New, shortData)
}
