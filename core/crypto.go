package core

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ericlagergren/siv"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
)

/*
Cipher identifies the authenticated cipher used to seal data.

Ciphertext is self-describing: the first byte tags which cipher sealed it, so
decryption always picks the right one no matter the current default.
*/
type Cipher byte

const (
	// CipherXSalsa20Poly1305 is XSalsa20-Poly1305 (NaCl secretbox) with a
	// 192-bit random nonce. This is the default.
	CipherXSalsa20Poly1305 Cipher = 0x01
	// CipherAES256GCMSIV is AES-256-GCM-SIV (RFC 8452) with a 96-bit
	// random nonce. A repeated nonce only reveals message equality.
	CipherAES256GCMSIV Cipher = 0x02
)

const (
	xsalsaOverhead = 1 + 24 + secretbox.Overhead // version + nonce + auth
	sivOverhead    = 1 + siv.NonceSize + siv.TagSize
)

// Overhead is the size by which the ciphertext exceeds the plaintext when
// sealed with the default cipher. Use OverheadFor with an explicit cipher.
const Overhead int = xsalsaOverhead

// OverheadFor returns the number of bytes by which a ciphertext sealed with
// the given cipher exceeds its plaintext, or zero for an unknown cipher.
func OverheadFor(c Cipher) int {
	switch c {
	case CipherXSalsa20Poly1305:
		return xsalsaOverhead
	case CipherAES256GCMSIV:
		return sivOverhead
	default:
		return 0
	}
}

var (
	defaultCipher   = CipherXSalsa20Poly1305
	defaultCipherMu sync.RWMutex
)

// SetDefaultCipher selects the cipher used by Encrypt, NewEnclave and Seal.
// It panics on an unknown cipher.
func SetDefaultCipher(c Cipher) {
	if OverheadFor(c) == 0 {
		panic("<memarmor::core> unknown cipher")
	}
	defaultCipherMu.Lock()
	defer defaultCipherMu.Unlock()
	defaultCipher = c
}

// DefaultCipher returns the cipher currently used by Encrypt, NewEnclave and Seal.
func DefaultCipher() Cipher {
	defaultCipherMu.RLock()
	defer defaultCipherMu.RUnlock()
	return defaultCipher
}

// ErrInvalidKeyLength is returned when attempting to encrypt or decrypt with a key that is not exactly 32 bytes in size.
var ErrInvalidKeyLength = errors.New("<memarmor::core::ErrInvalidKeyLength> key must be exactly 32 bytes")

// ErrBufferTooSmall is returned when the decryption function, Open, is given an output buffer that is too small to hold the plaintext. In practice the plaintext will be Overhead bytes smaller than the ciphertext returned by the encryption function, Seal.
var ErrBufferTooSmall = errors.New("<memarmor::core::ErrBufferTooSmall> the given buffer is too small to hold the plaintext")

// ErrDecryptionFailed is returned when the attempted decryption fails. This can occur if the given key is incorrect or if the ciphertext is invalid.
var ErrDecryptionFailed = errors.New("<memarmor::core::ErrDecryptionFailed> decryption failed: key is wrong or ciphertext is corrupt")

// Encrypt takes a plaintext message and a 32 byte key and returns an authenticated ciphertext sealed with the default cipher.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	return EncryptWithCipher(plaintext, key, DefaultCipher())
}

// EncryptWithCipher takes a plaintext message and a 32 byte key and returns an authenticated ciphertext sealed with the given cipher. It panics on an unknown cipher.
func EncryptWithCipher(plaintext, key []byte, c Cipher) ([]byte, error) {
	// Check the length of the key is correct.
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	switch c {
	case CipherXSalsa20Poly1305:
		// Get a reference to the key's underlying array without making a copy.
		k := (*[32]byte)(unsafe.Pointer(&key[0]))

		// Allocate space for and generate a nonce value.
		var nonce [24]byte
		if err := Scramble(nonce[:]); err != nil {
			Panic(err)
		}

		// Encrypt m and return the result.
		out := make([]byte, 1+len(nonce), 1+len(nonce)+len(plaintext)+secretbox.Overhead)
		out[0] = byte(CipherXSalsa20Poly1305)
		Copy(out[1:], nonce[:])
		return secretbox.Seal(out, plaintext, &nonce, k), nil
	case CipherAES256GCMSIV:
		aead, err := siv.NewGCM(key)
		if err != nil {
			return nil, ErrInvalidKeyLength // key is not 32 bytes long
		}

		// GCM-SIV tolerates random nonces: a repeat only leaks equality.
		var nonce [siv.NonceSize]byte
		if err := Scramble(nonce[:]); err != nil {
			Panic(err)
		}

		out := make([]byte, 1+siv.NonceSize, 1+siv.NonceSize+len(plaintext)+siv.TagSize)
		out[0] = byte(CipherAES256GCMSIV)
		Copy(out[1:], nonce[:])
		return aead.Seal(out, nonce[:], plaintext, nil), nil
	default:
		panic("<memarmor::core> unknown cipher")
	}
}

/*
Decrypt decrypts a given ciphertext with a given 32 byte key and writes the result to the start of a given buffer.

The cipher is selected automatically from the ciphertext's version tag. The
buffer must be large enough to contain the decrypted data. The size of the
decrypted data is returned. Callers must not rely on the contents of the
output buffer when an error is returned.
*/
func Decrypt(ciphertext, key []byte, output []byte) (int, error) {
	// Check the length of the key is correct.
	if len(key) != 32 {
		return 0, ErrInvalidKeyLength
	}

	// Identify the cipher from the version tag and reject truncated input
	// before touching any indexes below.
	if len(ciphertext) < 1 {
		return 0, ErrDecryptionFailed
	}
	overhead := OverheadFor(Cipher(ciphertext[0]))
	if overhead == 0 || len(ciphertext) <= overhead {
		return 0, ErrDecryptionFailed
	}

	// Check the capacity of the given output buffer.
	if cap(output) < (len(ciphertext) - overhead) {
		return 0, ErrBufferTooSmall
	}

	switch Cipher(ciphertext[0]) {
	case CipherXSalsa20Poly1305:
		// Get a reference to the key's underlying array without making a copy.
		k := (*[32]byte)(unsafe.Pointer(&key[0]))

		// Retrieve and store the nonce value.
		var nonce [24]byte
		Copy(nonce[:], ciphertext[1:1+24])

		// Decrypt directly into the caller's buffer. Authentication is
		// verified before anything is written, so a failure leaves the
		// output untouched and no plaintext ever touches the heap.
		m, ok := secretbox.Open(output[:0:cap(output)], ciphertext[1+24:], &nonce, k)
		if ok { // Decryption successful.
			return len(m), nil // Return length of decrypted plaintext.
		}
	case CipherAES256GCMSIV:
		aead, err := siv.NewGCM(key)
		if err != nil {
			return 0, ErrInvalidKeyLength // key is not 32 bytes long
		}

		// Decrypt directly into the caller's buffer. The output is wiped
		// if authentication fails.
		nonce := ciphertext[1 : 1+siv.NonceSize]
		m, err := aead.Open(output[:0:cap(output)], nonce, ciphertext[1+siv.NonceSize:], nil)
		if err == nil {
			return len(m), nil // Return length of decrypted plaintext.
		}
	}

	// Decryption unsuccessful. Either the key was wrong or the authentication failed.
	return 0, ErrDecryptionFailed
}

// Hash implements a cryptographic hash function using Blake2b.
func Hash(b []byte) []byte {
	h := blake2b.Sum256(b)
	return h[:]
}

// hash32 returns the Blake2b-256 digest as a value so callers can keep it in
// stack memory and wipe it afterwards, instead of letting a copy escape to
// the heap. Wipe the result as soon as it is no longer needed.
func hash32(b []byte) [32]byte {
	return blake2b.Sum256(b)
}

// Scramble fills a given buffer with cryptographically-secure random bytes.
func Scramble(buf []byte) error {
	if _, err := rand.Read(buf); err != nil {
		return err
	}

	// See Wipe
	runtime.KeepAlive(buf)
	return nil
}

//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
//go:noescape
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

// Wipe takes a buffer and wipes it with zeroes. The wipe is performed by the
// runtime's memory-clear routine, which the compiler cannot treat as a dead
// store the way it can a plain loop.
func Wipe(buf []byte) {
	if len(buf) == 0 {
		return
	}
	memclrNoHeapPointers(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
}

// Copy is identical to Go's builtin copy function. Copying needs no timing
// protection (only comparison does), so this is a plain copy.
func Copy(dst, src []byte) {
	copy(dst, src)
}

// Move is identical to Copy except it wipes the source buffer after the copy operation is executed.
func Move(dst, src []byte) {
	Copy(dst, src)
	Wipe(src)
}

// Equal does a constant-time comparison of two byte slices. This is to mitigate against side-channel attacks.
func Equal(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}
