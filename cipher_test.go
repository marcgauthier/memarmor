package memarmor

import (
	"bytes"
	"testing"
)

func TestCipherSelection(t *testing.T) {
	defer SetCipher(CipherXSalsa20Poly1305)

	SetCipher(CipherAES256GCMSIV)
	if GetCipher() != CipherAES256GCMSIV {
		t.Fatal("default cipher was not updated")
	}

	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	if e.Size() != 16 {
		t.Error("unexpected enclave size:", e.Size())
	}
	b, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("data does not match")
	}
	b.Destroy()

	// Explicit per-call choice keeps working no matter the default.
	e2 := NewEnclaveWithCipher([]byte("hello"), CipherXSalsa20Poly1305)
	if e2 == nil {
		t.Fatal("got nil enclave")
	}
	b2, err := e2.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(b2.Bytes(), []byte("hello")) {
		t.Error("data does not match")
	}
	b2.Destroy()

	// Seal path.
	lb := NewBufferFromBytes([]byte("sealed data"))
	e3 := lb.SealWithCipher(CipherAES256GCMSIV)
	if e3 == nil {
		t.Fatal("got nil enclave")
	}
	if lb.IsAlive() {
		t.Error("buffer was not consumed")
	}
	b3, err := e3.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(b3.Bytes(), []byte("sealed data")) {
		t.Error("data does not match")
	}
	b3.Destroy()

	if !panics(func() {
		SetCipher(Cipher(0x7f))
	}) {
		t.Error("SetCipher should panic on unknown cipher")
	}
}

func TestTopTPMSessionLock(t *testing.T) {
	defer Purge()

	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	switch TPMStatus() {
	case TPMSealed:
		if err := LockSessionKey(); err != nil {
			t.Fatal(err)
		}
		if TPMStatus() != TPMLocked {
			t.Fatal("expected locked state")
		}
		if _, err := e.Open(); err == nil {
			t.Error("expected open to fail while locked")
		}
		if NewEnclave([]byte("x")) != nil {
			t.Error("expected nil enclave while locked")
		}
		if err := UnlockSessionKey(); err != nil {
			t.Fatal(err)
		}
		b, err := e.Open()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
			t.Error("data mismatch after unlock")
		}
		b.Destroy()
	default:
		// No TPM seal here: locking must refuse, session keeps working.
		if err := LockSessionKey(); err == nil {
			t.Fatal("expected lock to refuse without a seal")
		}
		b, err := e.Open()
		if err != nil {
			t.Fatal(err)
		}
		b.Destroy()
	}
}

func TestTopEnclaveDestroy(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	e.Destroy()
	if e.Size() != 0 {
		t.Error("expected zero size after destroy")
	}
	if _, err := e.Open(); err == nil {
		t.Error("expected error opening destroyed enclave")
	}
	e.Destroy() // idempotent, must not panic
}
