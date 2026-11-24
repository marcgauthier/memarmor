package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
)

var (
	key        = &Coffer{}
	keyVersion uint64 // bumped each time the session key is recreated
	keyMtx     = sync.Mutex{}

	keyLocked bool   // session key evicted from RAM; sealed blob holds it
	sealedKey []byte // TPM-sealed session key (nil when TPM unused)
	sealPCRs  []int  // PCRs bound into future TPM seals (empty means none)
	tpmState  = TPMUnavailable
)

// keyAndVersion returns the live session key and its version atomically. It
// reports ErrSessionLocked while the key is locked in the TPM.
func keyAndVersion() (*Coffer, uint64, error) {
	if !sessionMu.TryRLock() {
		return nil, 0, ErrSessionBusy
	}
	defer finishSession()
	return sessionKey()
}

// sessionKey requires the session lock.
func sessionKey() (*Coffer, uint64, error) {
	keyMtx.Lock()
	defer keyMtx.Unlock()

	if keyLocked {
		return nil, 0, ErrSessionLocked
	}
	if key.Destroyed() {
		c, err := newCoffer()
		if err != nil {
			return nil, 0, err
		}
		sealedKey = nil
		if err = tpm.probe(); err != nil {
			tpmState = TPMUnavailable
		} else {
			sealedKey, err = sealAndVerify(c, sealPCRs)
			tpmState = TPMUnused
			if err == nil {
				tpmState = TPMSealed
			}
		}
		if len(sealPCRs) != 0 && sealedKey == nil {
			if cleanupErr := c.Destroy(); cleanupErr != nil {
				panic(cleanupErr)
			}
			return nil, 0, fmt.Errorf("%w: %w", ErrTPMPolicy, err)
		}
		key = c
		keyVersion++
	}

	return key, keyVersion, nil
}

// ErrNullEnclave is returned when attempting to construct an enclave of size less than one.
var ErrNullEnclave = errors.New("<memarmor::core::ErrNullEnclave> enclave size must be greater than zero")

const (
	// envelopeVersionSize is the plaintext session-key version header.
	envelopeVersionSize = 8
	// dekSealPlaintextSize is the wrapped key payload: version plus a 32-byte data key.
	dekSealPlaintextSize = 8 + 32
)

/*
Enclave is a sealed and encrypted container for sensitive data.

The envelope holds a session-key version header, the per-enclave data key
wrapped by the session key, and the data sealed under that data key. Every
enclave therefore uses a unique data key, so a nonce problem in one enclave
can never affect another, and the session key only ever wraps random keys.
*/
type Enclave struct {
	mu         sync.RWMutex
	ciphertext []byte
	adLen      int // associated-data prefix length; 0 for plain seals
}

/*
NewEnclave is a raw constructor for the Enclave object. The given buffer is wiped after the enclave is created.
*/
func NewEnclave(buf []byte) (*Enclave, error) {
	return NewEnclaveWithCipher(buf, DefaultCipher())
}

/*
NewEnclaveWithCipher is a raw constructor for the Enclave object that seals with the given cipher. The given buffer is wiped after the enclave is created.
*/
func NewEnclaveWithCipher(buf []byte, c Cipher) (*Enclave, error) {
	if !sessionMu.TryRLock() {
		return nil, ErrSessionBusy
	}
	defer finishSession()
	e, err := sealEnclave(buf, c)
	if err != nil {
		return nil, err
	}
	Wipe(buf)
	return e, nil
}

// sealEnclave requires the session lock and only reads buf.
func sealEnclave(buf []byte, c Cipher) (*Enclave, error) {
	if len(buf) < 1 {
		return nil, ErrNullEnclave
	}
	coffer, version, err := sessionKey()
	if err != nil {
		return nil, err
	}
	k, err := coffer.view()
	if err != nil {
		return nil, err
	}
	defer k.discard()

	dek, err := newBuffer(dekSealPlaintextSize)
	if err != nil {
		return nil, err
	}
	defer dek.discard()
	wrap := dek.Data()
	binary.BigEndian.PutUint64(wrap[:8], version)
	if err := Scramble(wrap[8:]); err != nil {
		return nil, err
	}
	wdek, err := encryptWithCipher(wrap, k.Data(), c)
	if err != nil {
		return nil, err
	}
	defer Wipe(wdek)
	dct, err := encryptWithCipher(buf, wrap[8:], c)
	if err != nil {
		return nil, err
	}
	defer Wipe(dct)

	e := &Enclave{ciphertext: make([]byte, envelopeVersionSize+len(wdek)+len(dct))}
	binary.BigEndian.PutUint64(e.ciphertext, version)
	Copy(e.ciphertext[envelopeVersionSize:], wdek)
	Copy(e.ciphertext[envelopeVersionSize+len(wdek):], dct)
	return e, nil
}

/*
NewEnclaveAD seals like NewEnclave but binds associated data into the seal.
Open it with OpenAD and the same associated data, reconstructed from expected
values rather than stored ones. The given buffer is wiped after sealing.
*/
func NewEnclaveAD(buf, ad []byte) (*Enclave, error) {
	return newEnclaveAD(buf, ad, true)
}

// NewEnclaveADCopy seals buf with associated data and preserves the source.
func NewEnclaveADCopy(buf, ad []byte) (*Enclave, error) {
	return newEnclaveAD(buf, ad, false)
}

func newEnclaveAD(buf, ad []byte, wipeSource bool) (*Enclave, error) {
	if len(buf) == 0 {
		return nil, ErrNullEnclave
	}
	if !sessionMu.TryRLock() {
		return nil, ErrSessionBusy
	}
	defer finishSession()
	plaintext := buf
	if len(ad) != 0 {
		if len(ad) > math.MaxInt-len(buf) {
			return nil, ErrAllocFailed
		}
		tmp, err := newBuffer(len(ad) + len(buf))
		if err != nil {
			return nil, err
		}
		defer tmp.discard()
		plaintext = tmp.Data()
		Copy(plaintext, ad)
		Copy(plaintext[len(ad):], buf)
	}
	e, err := sealEnclave(plaintext, DefaultCipher())
	if err != nil {
		return nil, err
	}
	e.adLen = len(ad)
	if wipeSource {
		Wipe(buf)
	}
	return e, nil
}

/*
Seal consumes a given Buffer object and returns its data secured and encrypted inside an Enclave. The given Buffer is destroyed after the Enclave is created.
*/
func Seal(b *Buffer) (*Enclave, error) {
	return SealWithCipher(b, DefaultCipher())
}

/*
SealWithCipher consumes a given Buffer object and returns its data secured and encrypted inside an Enclave sealed with the given cipher. The given Buffer is destroyed after the Enclave is created.
*/
func SealWithCipher(b *Buffer, c Cipher) (*Enclave, error) {
	if !sessionMu.TryRLock() {
		return nil, ErrSessionBusy
	}
	defer finishSession()

	b.Lock()
	defer b.Unlock()
	if !b.alive {
		return nil, ErrBufferExpired
	}
	e, err := sealEnclave(b.Data(), c)
	if err != nil {
		return nil, err
	}
	if err := b.destroyLocked(); err != nil {
		panic(err)
	}
	buffers.remove(b)
	return e, nil
}

// splitEnclave parses an envelope into its version, wrapped key and data
// seals. Foreign or truncated input reports ok == false.
func splitEnclave(blob []byte) (version uint64, wdek, data []byte, ok bool) {
	if len(blob) <= envelopeVersionSize+1 {
		return 0, nil, nil, false
	}
	version = binary.BigEndian.Uint64(blob[:envelopeVersionSize])
	rest := blob[envelopeVersionSize:]

	wOverhead := OverheadFor(Cipher(rest[0]))
	if wOverhead == 0 {
		return 0, nil, nil, false
	}
	wdekLen := dekSealPlaintextSize + wOverhead
	if len(rest) <= wdekLen+1 {
		return 0, nil, nil, false
	}
	wdek = rest[:wdekLen]
	data = rest[wdekLen:]

	dOverhead := OverheadFor(Cipher(data[0]))
	if dOverhead == 0 || len(data) <= dOverhead {
		return 0, nil, nil, false
	}
	return version, wdek, data, true
}

// unwrapDEK recovers an enclave's data key into a locked buffer, verifying
// that it was wrapped for the expected session-key version.
func unwrapDEK(wdek []byte, version uint64, kek []byte) (*Buffer, error) {
	dek, err := newBuffer(dekSealPlaintextSize)
	if err != nil {
		return nil, err
	}
	if _, err := decrypt(wdek, kek, dek.Data()); err != nil {
		dek.discard()
		return nil, err
	}

	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], version)
	match := Equal(dek.Data()[:8], vb[:])
	Wipe(vb[:])
	if !match {
		dek.discard()
		return nil, ErrDecryptionFailed
	}
	return dek, nil
}

// openEnvelope validates an envelope, checks the key version and unwraps the
// data key. The caller must destroy the returned key buffer.
func openEnvelope(e *Enclave) (data []byte, dek *Buffer, err error) {
	version, wdek, data, ok := splitEnclave(e.ciphertext)
	if !ok {
		return nil, nil, ErrDecryptionFailed
	}

	// Reject enclaves sealed under a previous session key before spending
	// any locked memory on them.
	coffer, current, err := sessionKey()
	if err != nil {
		return nil, nil, err
	}
	if version != current {
		return nil, nil, ErrDecryptionFailed
	}
	k, err := coffer.view()
	if err != nil {
		if err == ErrCofferExpired {
			return nil, nil, ErrDecryptionFailed
		}
		return nil, nil, err
	}

	// Unwrap the data key into locked memory.
	dek, err = unwrapDEK(wdek, version, k.Data())
	k.discard()
	if err != nil {
		return nil, nil, err
	}
	return data, dek, nil
}

/*
Open decrypts an Enclave and puts the contents into a Buffer object. The given Enclave is left untouched and may be reused.

The Buffer object should be destroyed after the contents are no longer needed.
*/
func Open(e *Enclave) (*Buffer, error) {
	if e == nil {
		return nil, ErrDecryptionFailed
	}
	if !sessionMu.TryRLock() {
		return nil, ErrSessionBusy
	}
	defer finishSession()
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.adLen != 0 {
		return nil, ErrDecryptionFailed // sealed with AD; use OpenAD
	}
	data, dek, err := openEnvelope(e)
	if err != nil {
		return nil, err
	}

	// Decrypt the data seal into the buffer we return.
	b, err := newBuffer(len(data) - OverheadFor(Cipher(data[0])))
	if err != nil {
		dek.discard()
		return nil, err
	}
	_, err = decrypt(data, dek.Data()[8:], b.Data())
	dek.discard()
	if err != nil {
		b.discard()
		return nil, err
	}

	// Return the contents of the Enclave inside a Buffer.
	return b, nil
}

/*
OpenAD opens an enclave sealed with NewEnclaveAD, verifying its associated
data against caller-supplied expected bytes. Anything else fails closed.
*/
func OpenAD(e *Enclave, ad []byte) (*Buffer, error) {
	if e == nil {
		return nil, ErrDecryptionFailed
	}
	if !sessionMu.TryRLock() {
		return nil, ErrSessionBusy
	}
	defer finishSession()
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(ad) != e.adLen {
		return nil, ErrDecryptionFailed
	}
	data, dek, err := openEnvelope(e)
	if err != nil {
		return nil, err
	}

	// Decrypt into a transient buffer, verify the prefix, then move the
	// payload alone into the buffer we return.
	tmp, err := newBuffer(len(data) - OverheadFor(Cipher(data[0])))
	if err != nil {
		dek.discard()
		return nil, err
	}
	_, err = decrypt(data, dek.Data()[8:], tmp.Data())
	dek.discard()
	if err != nil {
		tmp.discard()
		return nil, err
	}
	if len(tmp.Data()) <= len(ad) || !Equal(tmp.Data()[:len(ad)], ad) {
		tmp.discard()
		return nil, ErrDecryptionFailed
	}
	b, err := newBuffer(len(tmp.Data()) - len(ad))
	if err != nil {
		tmp.discard()
		return nil, err
	}
	Move(b.Data(), tmp.Data()[len(ad):])
	tmp.discard()
	return b, nil
}

/*
Destroy wipes the ciphertext held by an Enclave. The Enclave can no longer be
opened afterwards. Destroying an already-destroyed or nil Enclave is a no-op.
*/
func (e *Enclave) Destroy() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	Wipe(e.ciphertext)
	e.ciphertext = nil
	e.adLen = 0
}

/*
EnclaveOverhead returns the number of bytes by which an enclave sealed with
the given cipher exceeds its plaintext, or zero for an unknown cipher.
*/
func EnclaveOverhead(c Cipher) int {
	if o := OverheadFor(c); o > 0 {
		return envelopeVersionSize + dekSealPlaintextSize + 2*o
	}
	return 0
}

/*
EnclaveSize returns the number of bytes of plaintext data stored inside an Enclave.
*/
func EnclaveSize(e *Enclave) int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, _, data, ok := splitEnclave(e.ciphertext); ok {
		size := len(data) - OverheadFor(Cipher(data[0])) - e.adLen
		if size < 0 {
			return 0
		}
		return size
	}
	size := len(e.ciphertext) - Overhead
	if size < 0 {
		return 0
	}
	return size
}
