package memarmor

import (
	"github.com/marcgauthier/memarmor/core"
)

/*
Enclave is a sealed and encrypted container for sensitive data.
*/
type Enclave struct {
	*core.Enclave
}

/*
NewEnclave seals up some data into an encrypted enclave object. The buffer is wiped after the data is copied. If the length of the buffer is zero, the function will return nil.

A LockedBuffer may alternatively be converted into an Enclave object using its Seal method. This will also have the effect of destroying the LockedBuffer.
*/
func NewEnclave(src []byte) *Enclave {
	return NewEnclaveWithCipher(src, GetCipher())
}

/*
NewEnclaveWithCipher seals up some data into an encrypted enclave object using the given cipher. The buffer is wiped after the data is copied. If the length of the buffer is zero, the session key is locked in the TPM, or memory resources are exhausted, the function will return nil.
*/
func NewEnclaveWithCipher(src []byte, c Cipher) *Enclave {
	e, err := core.NewEnclaveWithCipher(src, c)
	if err != nil {
		if err == core.ErrNullEnclave || err == core.ErrSessionLocked || core.IsResourceError(err) {
			return nil
		}
		core.Panic(err)
	}
	return &Enclave{e}
}

/*
NewEnclaveRandom generates and seals arbitrary amounts of cryptographically-secure random bytes into an encrypted enclave object. If size is not strictly positive the function will return nil.
*/
func NewEnclaveRandom(size int) *Enclave {
	// todo: stream data into enclave
	b := NewBufferRandom(size)
	return b.Seal()
}

/*
NewEnclaveWithAD seals up some data like NewEnclave but binds associated data
into the seal. Open it with OpenWithAD and the same associated data. It
returns nil for empty input, a locked session, or exhausted memory resources.
*/
func NewEnclaveWithAD(src, ad []byte) *Enclave {
	e, err := core.NewEnclaveAD(src, ad)
	if err != nil {
		if err == core.ErrNullEnclave || err == core.ErrSessionLocked || core.IsResourceError(err) {
			return nil
		}
		core.Panic(err)
	}
	return &Enclave{e}
}

/*
OpenWithAD opens an enclave sealed with NewEnclaveWithAD, verifying its
associated data against caller-supplied expected bytes.
*/
func (e *Enclave) OpenWithAD(ad []byte) (*LockedBuffer, error) {
	b, err := core.OpenAD(e.Enclave, ad)
	if err != nil {
		if err != core.ErrDecryptionFailed && err != core.ErrSessionLocked && !core.IsResourceError(err) {
			core.Panic(err)
		}
		return nil, err
	}
	b.Freeze()
	return newBuffer(b), nil
}

/*
Open decrypts an Enclave object and places its contents into an immutable LockedBuffer. An error will be returned if decryption failed or the session key is locked in the TPM.
*/
func (e *Enclave) Open() (*LockedBuffer, error) {
	b, err := core.Open(e.Enclave)
	if err != nil {
		if err != core.ErrDecryptionFailed && err != core.ErrSessionLocked && !core.IsResourceError(err) {
			core.Panic(err)
		}
		return nil, err
	}
	b.Freeze()
	return newBuffer(b), nil
}

/*
Size returns the number of bytes of data stored within an Enclave.
*/
func (e *Enclave) Size() int {
	return core.EnclaveSize(e.Enclave)
}

/*
Destroy wipes the ciphertext held by an Enclave. The Enclave can no longer be
opened afterwards. Call it for enclaves you no longer need so their
ciphertext does not linger on the heap.
*/
func (e *Enclave) Destroy() {
	e.Enclave.Destroy()
}
