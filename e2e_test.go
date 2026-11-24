package memarmor

import (
	"bytes"
	"io"
	"testing"

	"github.com/marcgauthier/memarmor/core"
)

// TestEndToEndLifecycle runs a full application lifecycle the way a real
// program uses the library: seal secrets, stream data, survive a TPM
// lock/unlock cycle, then purge and start over. It runs once per cipher.
func TestEndToEndLifecycle(t *testing.T) {
	defer Purge()
	defer SetCipher(CipherXSalsa20Poly1305)

	for _, c := range []Cipher{CipherXSalsa20Poly1305, CipherAES256GCMSIV} {
		if !CipherAvailable(c) {
			continue
		}
		SetCipher(c)
		Purge() // fresh session per cipher
		lifecycle(t)
	}
}

func lifecycle(t *testing.T) {
	t.Helper()

	// 1. Seal application secrets, then open and use them.
	master := NewEnclaveRandom(32)
	if master == nil {
		t.Fatal("nil master enclave")
	}
	defer master.Destroy()

	tokenSrc := []byte("service-api-token")
	token := NewEnclave(tokenSrc)
	if token == nil {
		t.Fatal("nil token enclave")
	}
	defer token.Destroy()
	if !bytes.Equal(tokenSrc, make([]byte, len(tokenSrc))) {
		t.Error("seal input was not wiped")
	}

	mb, err := master.Open()
	if err != nil {
		t.Fatal(err)
	}
	if mb.Size() != 32 {
		t.Error("master key has wrong size")
	}
	mb.Destroy()

	tb, err := token.Open()
	if err != nil {
		t.Fatal(err)
	}
	if !tb.EqualTo([]byte("service-api-token")) {
		t.Error("token mismatch")
	}
	tb.Destroy()

	// 2. LockedBuffer scratch work plus a Seal round trip.
	scratch := NewBuffer(64)
	scratch.Copy([]byte("session state"))
	sealed := scratch.Seal()
	if scratch.IsAlive() {
		t.Error("sealed buffer was not consumed")
	}
	defer sealed.Destroy()
	sb, err := sealed.Open()
	if err != nil {
		t.Fatal(err)
	}
	if !sb.EqualTo(append([]byte("session state"), make([]byte, 64-13)...)) {
		t.Error("scratch data mismatch")
	}
	sb.Destroy()

	// 3. Stream a payload start to finish.
	s := NewStream()
	defer s.Destroy()
	payload := make([]byte, 3*StreamChunkSize+123)
	ScrambleBytes(payload)
	ref := append([]byte{}, payload...)
	if _, err := s.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Size() != len(ref) {
		t.Fatal("stream size mismatch")
	}
	back, err := s.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if !back.EqualTo(ref) {
		t.Error("stream data mismatch")
	}
	back.Destroy()
	if _, err := s.Read(make([]byte, 1)); err != io.EOF {
		t.Error("expected clean EOF; got", err)
	}

	// 4. TPM lock/unlock cycle when a seal exists.
	switch TPMStatus() {
	case TPMSealed:
		if err := LockSessionKey(); err != nil {
			t.Fatal(err)
		}
		if _, err := token.Open(); err != core.ErrSessionLocked {
			t.Fatalf("expected locked error; got %v", err)
		}
		if err := UnlockSessionKey(); err != nil {
			t.Fatal(err)
		}
		tb2, err := token.Open()
		if err != nil {
			t.Fatal("pre-lock enclave did not open after unlock:", err)
		}
		if !tb2.EqualTo([]byte("service-api-token")) {
			t.Error("token mismatch after unlock")
		}
		tb2.Destroy()
	default:
		if err := LockSessionKey(); err == nil {
			t.Fatal("expected lock to refuse without a seal")
		}
	}

	// 5. Purge retires everything; a fresh session works.
	Purge()
	if _, err := token.Open(); err != core.ErrDecryptionFailed {
		t.Fatalf("expected decryption failure after purge; got %v", err)
	}
	fresh := NewEnclave([]byte("next generation"))
	if fresh == nil {
		t.Fatal("fresh session broken")
	}
	defer fresh.Destroy()
	fb, err := fresh.Open()
	if err != nil {
		t.Fatal("fresh session broken:", err)
	}
	if !fb.EqualTo([]byte("next generation")) {
		t.Error("fresh data mismatch")
	}
	fb.Destroy()
}
