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

// MemArmor uses guarded hardware AES schedules and table-free POLYVAL.

// Package gcmsiv implements AES-GCM-SIV, the nonce misuse-resistant
// authenticated encryption algorithm specified in RFC 8452.
//
// It is a pure Go port of the AES-GCM-SIV implementation from AWS-LC
// (crypto/cipher_extra/e_aesgcmsiv.c), using only the Go standard library.
// AES uses hardware instructions and POLYVAL uses direct field multiplication.
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
	maxADLen        = 1 << 36
)

// errOpen is returned when decryption fails authentication or input
// limits are exceeded.
var errOpen = errors.New("gcmsiv: message authentication failed")

// Workspace contains the expanded keys and all secret block scratch. The
// caller supplies locked memory and wipes it after the operation.
type Workspace struct {
	master          aesBlock
	record          aesBlock
	decryptSchedule [60]uint32
	blocks          [3][16]byte
	material        [48]byte
}

type aesBlock struct {
	rounds int
	enc    [60]uint32
}

func (c *aesBlock) expand(key []byte, dec *[60]uint32) {
	c.rounds = len(key)/4 + 6
	expandKeyAsm(c.rounds, &key[0], &c.enc[0], &dec[0])
}

func (c *aesBlock) encrypt(dst, src *[16]byte) {
	encryptBlockAsm(c.rounds, &c.enc[0], &dst[0], &src[0])
}

type gcmsiv struct {
	work    *Workspace
	keySize int
}

// New initializes an operation in work. The workspace is single-use.
func New(key []byte, work *Workspace) (*gcmsiv, error) {
	if len(key) != KeySize128 && len(key) != KeySize256 {
		return nil, errors.New("gcmsiv: invalid key size")
	}
	if !Available() {
		return nil, errors.New("gcmsiv: hardware AES is unavailable")
	}
	work.master.expand(key, &work.decryptSchedule)
	return &gcmsiv{work: work, keySize: len(key)}, nil
}

func (g *gcmsiv) deriveKeys(nonce []byte) {
	w := g.work
	counter, ct := &w.blocks[0], &w.blocks[1]
	copy(counter[4:], nonce)
	clear(counter[1:4])
	for i := range (16 + g.keySize) / 8 {
		counter[0] = byte(i)
		w.master.encrypt(ct, counter)
		copy(w.material[i*8:], ct[:8])
	}
	w.record.expand(w.material[16:16+g.keySize], &w.decryptSchedule)
}

// auth computes the AES-GCM-SIV tag over plaintext and additional data
// (RFC 8452, Sections 3 and 4) and writes it to tag.
func auth(enc *aesBlock, authKey, nonce, plaintext, ad []byte, tag *[16]byte) {
	polyvalDirect(loadField(authKey), ad, plaintext).store(tag[:])
	binary.LittleEndian.PutUint64(tag[:], binary.LittleEndian.Uint64(tag[:])^binary.LittleEndian.Uint64(nonce))
	binary.LittleEndian.PutUint32(tag[8:], binary.LittleEndian.Uint32(tag[8:])^binary.LittleEndian.Uint32(nonce[8:]))
	tag[15] &= 0x7f
	enc.encrypt(tag, tag)
}

// crypt encrypts or decrypts in with the record key in AES-GCM-SIV counter
// mode: the counter is the tag with the top bit of the last byte set, and
// only the first four bytes advance, little-endian, wrapping modulo 2^32.
// in and out may be the same slice but must not otherwise overlap.
// counter and ks are scratch space.
func crypt(out, in []byte, tag *[16]byte, enc *aesBlock, counter, ks *[16]byte) {
	copy(counter[:], tag[:])
	counter[15] |= 0x80
	for len(in) >= 16 {
		enc.encrypt(ks, counter)
		binary.LittleEndian.PutUint32(counter[:], binary.LittleEndian.Uint32(counter[:])+1)
		binary.LittleEndian.PutUint64(out, binary.LittleEndian.Uint64(in)^binary.LittleEndian.Uint64(ks[:]))
		binary.LittleEndian.PutUint64(out[8:], binary.LittleEndian.Uint64(in[8:])^binary.LittleEndian.Uint64(ks[8:]))
		in = in[16:]
		out = out[16:]
	}
	if len(in) > 0 {
		enc.encrypt(ks, counter)
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
	w := g.work
	g.deriveKeys(nonce)
	auth(&w.record, w.material[:16], nonce, plaintext, ad, &w.blocks[2])
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	crypt(out[:len(plaintext)], plaintext, &w.blocks[2], &w.record, &w.blocks[0], &w.blocks[1])
	copy(out[len(plaintext):], w.blocks[2][:])
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
	if uint64(len(in)) > maxPlaintextLen || uint64(len(ad)) > maxADLen {
		return nil, errOpen
	}
	w := g.work
	g.deriveKeys(nonce)
	var tag [16]byte
	copy(tag[:], claimed)
	ret, out := sliceForAppend(dst, len(in))
	crypt(out, in, &tag, &w.record, &w.blocks[0], &w.blocks[1])
	auth(&w.record, w.material[:16], nonce, out, ad, &w.blocks[2])
	if subtle.ConstantTimeCompare(w.blocks[2][:], tag[:]) != 1 {
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
