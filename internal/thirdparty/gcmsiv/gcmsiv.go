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

// MemArmor uses 64-bit length comparisons so this file builds on 32-bit Go.

// Package gcmsiv implements AES-GCM-SIV, the nonce misuse-resistant
// authenticated encryption algorithm specified in RFC 8452.
//
// It is a pure Go port of the AES-GCM-SIV implementation from AWS-LC
// (crypto/cipher_extra/e_aesgcmsiv.c), using only the Go standard library.
// The AES block function comes from crypto/aes (hardware accelerated where
// the platform supports it); POLYVAL is implemented natively, with direct
// dot products for short inputs and precomputed multiplication tables for
// long ones.
//
// Supported key sizes are 16 bytes (AEAD_AES_128_GCM_SIV) and 32 bytes
// (AEAD_AES_256_GCM_SIV). Nonces are 12 bytes and tags are 16 bytes.
//
// # Nonce misuse resistance
//
// Unlike AES-GCM, repeating a nonce does not catastrophically destroy
// confidentiality: at worst it reveals whether the same (nonce, plaintext,
// additional data) tuple was encrypted twice, like a deterministic
// encryption scheme. Repeating nonces must still be avoided whenever
// possible, and must never be combined with attacker-chosen plaintexts
// beyond the inherent equality leakage.
package gcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Sizes in bytes.
const (
	// NonceSize is the size of the AES-GCM-SIV nonce.
	NonceSize = 12
	// TagSize is the size of the AES-GCM-SIV authentication tag.
	TagSize = 16
	// KeySize128 is the key size of AEAD_AES_128_GCM_SIV.
	KeySize128 = 16
	// KeySize256 is the key size of AEAD_AES_256_GCM_SIV.
	KeySize256 = 32
)

// Input limits from RFC 8452, Section 6 (mirroring AWS-LC).
const (
	maxPlaintextLen = 1 << 36
	maxADLen        = (1 << 61) - 1
)

// errOpen is returned when decryption fails authentication or input
// limits are exceeded.
var errOpen = errors.New("gcmsiv: message authentication failed")

// directDotsThreshold is the maximum number of POLYVAL blocks (AD plus
// plaintext/ciphertext plus the length block) processed with direct dot
// multiplications. Short inputs skip the table setup this way; longer
// inputs amortize the tables. Tuned by benchmark (see BenchmarkPolyval*).
var directDotsThreshold = 14

// gcmsiv is a cipher.AEAD implementing AES-GCM-SIV. It holds only the
// expanded master key; per-message keys and POLYVAL tables are derived per
// call, so a single instance is safe for concurrent use.
type gcmsiv struct {
	master cipher.Block
	is256  bool
}

var _ cipher.AEAD = (*gcmsiv)(nil)

// New returns a cipher.AEAD implementing AES-GCM-SIV with the given key.
// The key must be 16 bytes (AES-128-GCM-SIV) or 32 bytes (AES-256-GCM-SIV).
func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case KeySize128, KeySize256:
	default:
		return nil, errors.New("gcmsiv: invalid key size (want 16 or 32 bytes)")
	}
	master, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &gcmsiv{master: master, is256: len(key) == KeySize256}, nil
}

// NonceSize returns the required nonce size in bytes.
func (g *gcmsiv) NonceSize() int { return NonceSize }

// Overhead returns the tag size in bytes.
func (g *gcmsiv) Overhead() int { return TagSize }

// scratchPad holds the 16-byte scratch blocks a Seal/Open call needs. It is
// threaded through the call chain so the blocks escape to the heap once,
// together, instead of once each at every cipher.Block call.
type scratchPad struct {
	buf [3][16]byte
}

// deriveKeys runs the AES-GCM-SIV key derivation (RFC 8452, Section 4):
// it encrypts counter blocks holding the nonce with the master key,
// keeping 8 bytes of each ciphertext. It writes the POLYVAL authentication
// key to auth and returns the record encryption block cipher. counter and
// ct are scratch space.
func (g *gcmsiv) deriveKeys(nonce []byte, auth, counter, ct *[16]byte) cipher.Block {
	copy(counter[4:], nonce)
	clear(counter[1:4]) // counter is reused scratch; bytes 1..3 must be zero
	blocks := 4
	if g.is256 {
		blocks = 6
	}
	var material [48]byte
	for i := 0; i < blocks; i++ {
		counter[0] = byte(i)
		g.master.Encrypt(ct[:], counter[:])
		copy(material[i*8:], ct[:8])
	}
	copy(auth[:], material[:16])
	// The key length is 16 or 32 by construction, so NewCipher cannot fail.
	enc, _ := aes.NewCipher(material[16 : 16+g.encKeyLen()])
	return enc
}

func (g *gcmsiv) encKeyLen() int {
	if g.is256 {
		return KeySize256
	}
	return KeySize128
}

// auth computes the AES-GCM-SIV tag over plaintext and additional data
// (RFC 8452, Sections 3 and 4) and writes it to tag.
func auth(enc cipher.Block, authKey *[16]byte, nonce, plaintext, ad []byte, tag *[16]byte) {
	h := loadField(authKey[:])
	dots := len(ad)/16 + len(plaintext)/16 + 1
	if len(ad)&15 != 0 {
		dots++
	}
	if len(plaintext)&15 != 0 {
		dots++
	}
	var s field
	if dots <= directDotsThreshold {
		s = polyvalDirect(h, ad, plaintext)
	} else {
		s = polyval(dotKey(h), ad, plaintext)
	}
	s.store(tag[:])
	binary.LittleEndian.PutUint64(tag[:], binary.LittleEndian.Uint64(tag[:])^binary.LittleEndian.Uint64(nonce))
	binary.LittleEndian.PutUint32(tag[8:], binary.LittleEndian.Uint32(tag[8:])^binary.LittleEndian.Uint32(nonce[8:]))
	tag[15] &= 0x7f
	enc.Encrypt(tag[:], tag[:])
}

// crypt encrypts or decrypts in with the record key in AES-GCM-SIV counter
// mode: the counter is the tag with the top bit of the last byte set, and
// only the first four bytes advance, little-endian, wrapping modulo 2^32.
// in and out may be the same slice but must not otherwise overlap.
// counter and ks are scratch space.
func crypt(out, in []byte, tag *[16]byte, enc cipher.Block, counter, ks *[16]byte) {
	copy(counter[:], tag[:])
	counter[15] |= 0x80
	for len(in) >= 16 {
		enc.Encrypt(ks[:], counter[:])
		binary.LittleEndian.PutUint32(counter[:], binary.LittleEndian.Uint32(counter[:])+1)
		binary.LittleEndian.PutUint64(out, binary.LittleEndian.Uint64(in)^binary.LittleEndian.Uint64(ks[:]))
		binary.LittleEndian.PutUint64(out[8:], binary.LittleEndian.Uint64(in[8:])^binary.LittleEndian.Uint64(ks[8:]))
		in = in[16:]
		out = out[16:]
	}
	if len(in) > 0 {
		enc.Encrypt(ks[:], counter[:])
		for i := range in {
			out[i] = in[i] ^ ks[i]
		}
	}
}

// Seal encrypts plaintext with nonce and additional data, appends the
// result (ciphertext plus tag) to dst and returns the updated slice.
// The nonce must be NonceSize bytes long. Like other cipher.AEAD
// implementations, Seal panics on invalid input sizes.
func (g *gcmsiv) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(nonce) != NonceSize {
		panic("gcmsiv: incorrect nonce length")
	}
	if uint64(len(plaintext)) > maxPlaintextLen {
		panic("gcmsiv: plaintext too large")
	}
	if uint64(len(ad)) > maxADLen {
		panic("gcmsiv: additional data too large")
	}
	var authKey [16]byte
	var sc scratchPad
	enc := g.deriveKeys(nonce, &authKey, &sc.buf[0], &sc.buf[1])
	auth(enc, &authKey, nonce, plaintext, ad, &sc.buf[2])
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	crypt(out[:len(plaintext)], plaintext, &sc.buf[2], enc, &sc.buf[0], &sc.buf[1])
	copy(out[len(plaintext):], sc.buf[2][:])
	return ret
}

// Open decrypts ciphertext (which must include the trailing tag) with
// nonce and additional data, appends the plaintext to dst and returns the
// updated slice. It returns an error if authentication fails. The nonce
// must be NonceSize bytes long.
func (g *gcmsiv) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("gcmsiv: incorrect nonce length")
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}
	in, claimed := ciphertext[:len(ciphertext)-TagSize], ciphertext[len(ciphertext)-TagSize:]
	// AWS-LC tolerates 2^36+16 bytes here so overlong inputs fail
	// authentication rather than tripping the length check first.
	if uint64(len(in)) > maxPlaintextLen+16 {
		return nil, errOpen
	}
	if uint64(len(ad)) > maxADLen {
		return nil, errOpen
	}
	var authKey [16]byte
	var sc scratchPad
	enc := g.deriveKeys(nonce, &authKey, &sc.buf[0], &sc.buf[1])
	var tag [16]byte
	copy(tag[:], claimed)
	ret, out := sliceForAppend(dst, len(in))
	crypt(out, in, &tag, enc, &sc.buf[0], &sc.buf[1])
	auth(enc, &authKey, nonce, out, ad, &sc.buf[2])
	if subtle.ConstantTimeCompare(sc.buf[2][:], tag[:]) != 1 {
		// Zero the unauthenticated plaintext before failing.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

// sliceForAppend behaves like append, growing in only when needed. It
// returns the grown slice and the tail that the caller must fill.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
