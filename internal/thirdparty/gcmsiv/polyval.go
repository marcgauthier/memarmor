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
// dot(a, b) = a * b * x^-128.

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

// polyvalDirect evaluates POLYVAL over AD, data, and the length block
// without lookups indexed by input or key material.
func polyvalDirect(h field, ad, data []byte) field {
	s := feedPolyval(field{}, h, ad)
	s = feedPolyval(s, h, data)
	return dot(s.xor(field{lo: uint64(len(ad)) * 8, hi: uint64(len(data)) * 8}), h)
}

func feedPolyval(s, h field, data []byte) field {
	for len(data) >= 16 {
		s = dot(s.xor(loadField(data)), h)
		data = data[16:]
	}
	if len(data) != 0 {
		var tail field
		for i, b := range data {
			if i < 8 {
				tail.lo |= uint64(b) << (8 * i)
			} else {
				tail.hi |= uint64(b) << (8 * (i - 8))
			}
		}
		s = dot(s.xor(tail), h)
	}
	return s
}
