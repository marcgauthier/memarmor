// Copyright 2026 marcgauthier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcmsiv

import "encoding/binary"

// This file implements POLYVAL, the polynomial authenticator used by
// AES-GCM-SIV (RFC 8452, Section 3).
//
// POLYVAL operates in GF(2^128) defined by the irreducible polynomial
// x^128 + x^127 + x^126 + x^121 + 1. Field elements map to 16-byte
// strings little-endian: the least significant bit of the first byte is
// the coefficient of x^0.
//
// The POLYVAL iteration is S_j = dot(S_{j-1} + X_j, H) where
// dot(a, b) = a * b * x^-128. Since dot(a, H) = a * (H * x^-128), the
// package precomputes H' = H * x^-128 once per message (via the static
// xinvTable below) and then uses plain field multiplication by H' with
// precomputed Shoup-like tables.

// field is a POLYVAL field element, stored as two little-endian words:
// bit i of the polynomial is bit i of lo+hi*2^64.
type field struct {
	lo, hi uint64
}

func loadField(b []byte) field {
	return field{
		lo: binary.LittleEndian.Uint64(b),
		hi: binary.LittleEndian.Uint64(b[8:]),
	}
}

func (f field) store(b []byte) {
	binary.LittleEndian.PutUint64(b, f.lo)
	binary.LittleEndian.PutUint64(b[8:], f.hi)
}

func (f field) xor(g field) field {
	return field{f.lo ^ g.lo, f.hi ^ g.hi}
}

// redHi holds bits 121, 126 and 127 of the reduction polynomial
// x^128 + x^127 + x^126 + x^121 + 1, i.e. the high word xored on
// overflow when multiplying by x: (1<<63)|(1<<62)|(1<<57).
const redHi = 0xC200000000000000

// dbl multiplies x by the field element x (branchless).
func dbl(x field) field {
	carry := x.hi >> 63
	hi := x.hi<<1 | x.lo>>63
	lo := x.lo<<1 ^ carry
	hi ^= (0 - carry) & redHi
	return field{lo, hi}
}

// xinvValue is x^-128 = x^127 + x^124 + x^121 + x^114 + 1
// (RFC 8452, Section 3).
var xinvValue = field{lo: 1, hi: 0x9204000000000000}

// xinvTable holds nibble multiplication tables for the constant x^-128,
// used to derive H' = H * x^-128 once per message. It is built once at
// init time and read-only afterwards.
var xinvTable table4

func init() {
	xinvTable.build(xinvValue)
}

// dotKey returns H' = H * x^-128, so that dot(s, H) == mul(s, H').
func dotKey(h field) field {
	return xinvTable.mul(h)
}

// table4 holds 32 nibble tables for plain field multiplication by a fixed
// key: t[i][v] = key * (v * x^(4*i)).
type table4 struct {
	t [32][16]field
}

func (t *table4) build(h field) {
	// First derive all T[i][1] = h*x^(4*i) through one doubling chain,
	// then fill in the remaining entries table by table. The fills are
	// independent of each other, which lets the CPU overlap them.
	t.t[0][0] = field{}
	t.t[0][1] = h
	x := h
	for i := 1; i < 32; i++ {
		x = dbl(dbl(dbl(dbl(x))))
		t.t[i][0] = field{}
		t.t[i][1] = x
	}
	for i := 0; i < 32; i++ {
		x := t.t[i][1]
		t2 := dbl(x)
		t.t[i][2], t.t[i][3] = t2, t2.xor(x)
		t4 := dbl(t2)
		t.t[i][4], t.t[i][5] = t4, t4.xor(x)
		t6 := dbl(t.t[i][3])
		t.t[i][6], t.t[i][7] = t6, t6.xor(x)
		t8 := dbl(t4)
		t.t[i][8], t.t[i][9] = t8, t8.xor(x)
		t10 := dbl(t.t[i][5])
		t.t[i][10], t.t[i][11] = t10, t10.xor(x)
		t12 := dbl(t6)
		t.t[i][12], t.t[i][13] = t12, t12.xor(x)
		t14 := dbl(t.t[i][7])
		t.t[i][14], t.t[i][15] = t14, t14.xor(x)
	}
}

// mul returns s * key using the precomputed tables. Fully unrolled with
// four accumulators to expose instruction-level parallelism.
func (t *table4) mul(s field) field {
	lo, hi := s.lo, s.hi
	var r0, r1, r2, r3 field
	e := t.t[0][lo&0xf]
	r0.lo, r0.hi = e.lo, e.hi
	e = t.t[1][(lo>>4)&0xf]
	r1.lo, r1.hi = e.lo, e.hi
	e = t.t[2][(lo>>8)&0xf]
	r2.lo, r2.hi = e.lo, e.hi
	e = t.t[3][(lo>>12)&0xf]
	r3.lo, r3.hi = e.lo, e.hi
	e = t.t[4][(lo>>16)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[5][(lo>>20)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[6][(lo>>24)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[7][(lo>>28)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[8][(lo>>32)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[9][(lo>>36)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[10][(lo>>40)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[11][(lo>>44)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[12][(lo>>48)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[13][(lo>>52)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[14][(lo>>56)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[15][(lo>>60)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[16][hi&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[17][(hi>>4)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[18][(hi>>8)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[19][(hi>>12)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[20][(hi>>16)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[21][(hi>>20)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[22][(hi>>24)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[23][(hi>>28)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[24][(hi>>32)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[25][(hi>>36)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[26][(hi>>40)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[27][(hi>>44)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[28][(hi>>48)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[29][(hi>>52)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[30][(hi>>56)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[31][(hi>>60)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	return field{
		lo: r0.lo ^ r1.lo ^ r2.lo ^ r3.lo,
		hi: r0.hi ^ r1.hi ^ r2.hi ^ r3.hi,
	}
}

// update runs the POLYVAL iteration over whole blocks: s = (s + X) * key.
func (t *table4) update(s field, data []byte) field {
	for len(data) >= 16 {
		s.lo ^= binary.LittleEndian.Uint64(data)
		s.hi ^= binary.LittleEndian.Uint64(data[8:])
		s = t.mul(s)
		data = data[16:]
	}
	return s
}

// Lane masks selecting every fourth bit, used to evaluate carryless
// multiplication with integer multiplies (technique as in BoringSSL's
// gcm_nohw.c).
const (
	lane0_32 uint32 = 0x11111111
	lane1_32 uint32 = 0x22222222
	lane2_32 uint32 = 0x44444444
	lane3_32 uint32 = 0x88888888
	lane0_64 uint64 = 0x1111111111111111
	lane1_64 uint64 = 0x2222222222222222
	lane2_64 uint64 = 0x4444444444444444
	lane3_64 uint64 = 0x8888888888888888
)

// clmul32 carryless-multiplies two 32-bit polynomials. The inputs are split
// into nibble lanes; within a lane pair the integer product's matching lane
// equals the carryless product, and combining lane pairs recovers the full
// 64-bit result.
func clmul32(a, b uint32) uint64 {
	a0 := uint64(a & lane0_32)
	a1 := uint64(a & lane1_32)
	a2 := uint64(a & lane2_32)
	a3 := uint64(a & lane3_32)
	b0 := uint64(b & lane0_32)
	b1 := uint64(b & lane1_32)
	b2 := uint64(b & lane2_32)
	b3 := uint64(b & lane3_32)
	c0 := a0*b0 ^ a1*b3 ^ a2*b2 ^ a3*b1
	c1 := a0*b1 ^ a1*b0 ^ a2*b3 ^ a3*b2
	c2 := a0*b2 ^ a1*b1 ^ a2*b0 ^ a3*b3
	c3 := a0*b3 ^ a1*b2 ^ a2*b1 ^ a3*b0
	return c0&lane0_64 | c1&lane1_64 | c2&lane2_64 | c3&lane3_64
}

// clmul64 carryless-multiplies two 64-bit polynomials with one Karatsuba
// step over clmul32.
func clmul64(a, b uint64) field {
	a0 := uint32(a)
	a1 := uint32(a >> 32)
	b0 := uint32(b)
	b1 := uint32(b >> 32)
	lo := clmul32(a0, b0)
	hi := clmul32(a1, b1)
	mid := clmul32(a0^a1, b0^b1) ^ lo ^ hi
	return field{lo: lo ^ mid<<32, hi: hi ^ mid>>32}
}

// dot multiplies a and b and then by x^-128 (RFC 8452, Section 3), computed
// directly without tables. From the modulus, x^-128 = 1+x^-1+x^-2+x^-7, so
// with the 256-bit product r = r1*x^128+r0 the result is
// r1 + r0*(1+x^-1+x^-2+x^-7); the first line folds r0's low bits that would
// shift out into r0.hi so a single pass suffices.
func dot(a, b field) field {
	r0 := clmul64(a.lo, b.lo)
	r1 := clmul64(a.hi, b.hi)
	mid := clmul64(a.lo^a.hi, b.lo^b.hi)
	mid.lo ^= r0.lo ^ r1.lo
	mid.hi ^= r0.hi ^ r1.hi
	r1.lo ^= mid.hi
	r0.hi ^= mid.lo

	r0.hi ^= r0.lo<<63 ^ r0.lo<<62 ^ r0.lo<<57
	r1.lo ^= r0.lo
	r1.hi ^= r0.hi
	r1.lo ^= r0.lo>>1 ^ r0.hi<<63
	r1.hi ^= r0.hi >> 1
	r1.lo ^= r0.lo>>2 ^ r0.hi<<62
	r1.hi ^= r0.hi >> 2
	r1.lo ^= r0.lo>>7 ^ r0.hi<<57
	r1.hi ^= r0.hi >> 7
	return r1
}

// polyvalDirect evaluates POLYVAL over ad, data and the length block with
// direct dot multiplications. It has no setup cost, so it wins for short
// inputs where building tables would dominate.
func polyvalDirect(h field, ad, data []byte) field {
	s := field{}
	feed := func(blocks []byte) {
		for len(blocks) >= 16 {
			s = dot(s.xor(loadField(blocks)), h)
			blocks = blocks[16:]
		}
	}
	feed(ad)
	if rem := len(ad) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], ad[len(ad)-rem:])
		s = dot(s.xor(loadField(blk[:])), h)
	}
	feed(data)
	if rem := len(data) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], data[len(data)-rem:])
		s = dot(s.xor(loadField(blk[:])), h)
	}
	var lb [16]byte
	binary.LittleEndian.PutUint64(lb[:], uint64(len(ad))*8)
	binary.LittleEndian.PutUint64(lb[8:], uint64(len(data))*8)
	return dot(s.xor(loadField(lb[:])), h)
}

// polyval evaluates POLYVAL with dot-key hp over ad, data and the
// length block.
func polyval(hp field, ad, data []byte) field {
	var t table4
	t.build(hp)
	s := field{}
	s = t.update(s, ad)
	if rem := len(ad) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], ad[len(ad)-rem:])
		s = s.xor(loadField(blk[:]))
		s = t.mul(s)
	}
	s = t.update(s, data)
	if rem := len(data) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], data[len(data)-rem:])
		s = s.xor(loadField(blk[:]))
		s = t.mul(s)
	}
	var lb [16]byte
	binary.LittleEndian.PutUint64(lb[:], uint64(len(ad))*8)
	binary.LittleEndian.PutUint64(lb[8:], uint64(len(data))*8)
	s = s.xor(loadField(lb[:]))
	return t.mul(s)
}
