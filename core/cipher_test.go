package core

import (
	"bytes"
	"testing"
)

var testCiphers = []Cipher{CipherXSalsa20Poly1305, CipherAES256GCMSIV}

func TestOverheadFor(t *testing.T) {
	if OverheadFor(CipherXSalsa20Poly1305) != Overhead {
		t.Error("XSalsa overhead does not match Overhead const")
	}
	// version byte + 12 byte nonce + 16 byte tag
	if OverheadFor(CipherAES256GCMSIV) != 1+12+16 {
		t.Error("unexpected SIV overhead:", OverheadFor(CipherAES256GCMSIV))
	}
	if OverheadFor(Cipher(0x7f)) != 0 {
		t.Error("expected zero overhead for unknown cipher")
	}
}

func TestEncryptWithCipherRoundTrip(t *testing.T) {
	m := make([]byte, 64)
	Scramble(m)
	k := make([]byte, 32)
	Scramble(k)

	for _, c := range testCiphers {
		x, err := EncryptWithCipher(m, k, c)
		if err != nil {
			t.Fatalf("cipher %d: unexpected encrypt error: %s", c, err)
		}
		if Cipher(x[0]) != c {
			t.Errorf("cipher %d: missing version tag; got %x", c, x[0])
		}
		if len(x) != len(m)+OverheadFor(c) {
			t.Errorf("cipher %d: unexpected length %d", c, len(x))
		}

		dm := make([]byte, len(m))
		n, err := Decrypt(x, k, dm)
		if err != nil {
			t.Errorf("cipher %d: unexpected decrypt error: %s", c, err)
		}
		if n != len(m) {
			t.Errorf("cipher %d: unexpected plaintext length %d", c, n)
		}
		if !bytes.Equal(m, dm) {
			t.Errorf("cipher %d: decrypted plaintext does not match", c)
		}
	}
}

func TestDecryptRejects(t *testing.T) {
	m := make([]byte, 64)
	Scramble(m)
	k := make([]byte, 32)
	Scramble(k)
	wrong := make([]byte, 32)
	Scramble(wrong)

	corrupt := func(x []byte) [][]byte {
		nonce := make([]byte, len(x))
		copy(nonce, x)
		nonce[2] ^= 0xff // corrupt a nonce byte

		body := make([]byte, len(x))
		copy(body, x)
		body[len(body)-1] ^= 0xff // corrupt body/tag

		version := make([]byte, len(x))
		copy(version, x)
		version[0] = 0x7f // unknown version

		swap := make([]byte, len(x))
		copy(swap, x)
		if swap[0] == byte(CipherXSalsa20Poly1305) {
			swap[0] = byte(CipherAES256GCMSIV)
		} else {
			swap[0] = byte(CipherXSalsa20Poly1305)
		}

		return [][]byte{nonce, body, version, swap, x[:5], {}}
	}

	for _, c := range testCiphers {
		x, err := EncryptWithCipher(m, k, c)
		if err != nil {
			t.Fatalf("cipher %d: unexpected encrypt error: %s", c, err)
		}
		// Generously sized so every corrupt case reaches authentication.
		dm := make([]byte, len(x))

		for i, bad := range corrupt(x) {
			n, err := Decrypt(bad, k, dm)
			if n != 0 || err != ErrDecryptionFailed {
				t.Errorf("cipher %d case %d: expected decryption failure; got %d, %s", c, i, n, err)
			}
		}

		// Wrong key.
		if n, err := Decrypt(x, wrong, dm); n != 0 || err != ErrDecryptionFailed {
			t.Errorf("cipher %d: expected failure with wrong key; got %d, %s", c, n, err)
		}

		// Output buffer too small.
		small := make([]byte, len(m)-1)
		if n, err := Decrypt(x, k, small); n != 0 || err != ErrBufferTooSmall {
			t.Errorf("cipher %d: expected small-buffer error; got %d, %s", c, n, err)
		}

		// Invalid key length.
		short := make([]byte, 16)
		if _, err := EncryptWithCipher(m, short, c); err != ErrInvalidKeyLength {
			t.Errorf("cipher %d: expected invalid-key error on encrypt; got %s", c, err)
		}
		if n, err := Decrypt(x, short, dm); n != 0 || err != ErrInvalidKeyLength {
			t.Errorf("cipher %d: expected invalid-key error on decrypt; got %d, %s", c, n, err)
		}
	}
}

func TestDecryptAvoidsHeapPlaintext(t *testing.T) {
	k := make([]byte, 32)
	Scramble(k)
	m := make([]byte, 64)
	Scramble(m)

	// The XSalsa path must decrypt straight into the caller's buffer. Zero
	// allocations proves no plaintext copy can linger on the heap.
	x, err := EncryptWithCipher(m, k, CipherXSalsa20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	dm := make([]byte, len(m))
	if allocs := testing.AllocsPerRun(100, func() {
		if _, err := Decrypt(x, k, dm); err != nil {
			t.Error(err)
		}
	}); allocs != 0 {
		t.Error("XSalsa decrypt allocated on the heap:", allocs)
	}
}

func TestDefaultCipherSelection(t *testing.T) {
	defer SetDefaultCipher(CipherXSalsa20Poly1305)

	m := make([]byte, 32)
	Scramble(m)
	k := make([]byte, 32)
	Scramble(k)

	// Ciphertext created under one default must still open after switching,
	// since the format is self-describing.
	SetDefaultCipher(CipherAES256GCMSIV)
	siv, err := Encrypt(m, k)
	if err != nil {
		t.Fatal(err)
	}
	if Cipher(siv[0]) != CipherAES256GCMSIV {
		t.Fatal("Encrypt did not use the default cipher")
	}

	SetDefaultCipher(CipherXSalsa20Poly1305)
	box, err := Encrypt(m, k)
	if err != nil {
		t.Fatal(err)
	}
	if Cipher(box[0]) != CipherXSalsa20Poly1305 {
		t.Fatal("Encrypt did not use the default cipher")
	}

	dm := make([]byte, len(m))
	if _, err := Decrypt(siv, k, dm); err != nil {
		t.Error("SIV ciphertext did not open under XSalsa default:", err)
	}
	if _, err := Decrypt(box, k, dm); err != nil {
		t.Error("XSalsa ciphertext did not open:", err)
	}
	if DefaultCipher() != CipherXSalsa20Poly1305 {
		t.Error("unexpected default cipher")
	}
}

func TestInvalidCipherPanics(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error("SetDefaultCipher accepted an unknown cipher")
			}
		}()
		SetDefaultCipher(Cipher(0x7f))
	}()

	func() {
		defer func() {
			if recover() == nil {
				t.Error("EncryptWithCipher accepted an unknown cipher")
			}
		}()
		k := make([]byte, 32)
		_, _ = EncryptWithCipher([]byte("x"), k, Cipher(0x7f))
	}()
}

func TestEnclaveWithCipher(t *testing.T) {
	for _, c := range testCiphers {
		data := []byte("yellow submarine")
		e, err := NewEnclaveWithCipher(data, c)
		if err != nil {
			t.Fatalf("cipher %d: %s", c, err)
		}
		if !bytes.Equal(data, make([]byte, 16)) {
			t.Errorf("cipher %d: input was not wiped", c)
		}
		if len(e.ciphertext) != 16+EnclaveOverhead(c) {
			t.Errorf("cipher %d: unexpected length %d", c, len(e.ciphertext))
		}
		if EnclaveSize(e) != 16 {
			t.Errorf("cipher %d: unexpected enclave size %d", c, EnclaveSize(e))
		}

		buf, err := Open(e)
		if err != nil {
			t.Fatalf("cipher %d: %s", c, err)
		}
		if !bytes.Equal(buf.Data(), []byte("yellow submarine")) {
			t.Errorf("cipher %d: decrypted data does not match", c)
		}
		buf.Destroy()

		// Seal path.
		b, err := NewBuffer(16)
		if err != nil {
			t.Fatal(err)
		}
		Copy(b.Data(), []byte("0123456789abcdef"))
		se, err := SealWithCipher(b, c)
		if err != nil {
			t.Fatalf("cipher %d: %s", c, err)
		}
		if b.Alive() {
			t.Errorf("cipher %d: buffer was not consumed", c)
		}
		buf, err = Open(se)
		if err != nil {
			t.Fatalf("cipher %d: %s", c, err)
		}
		if !bytes.Equal(buf.Data(), []byte("0123456789abcdef")) {
			t.Errorf("cipher %d: sealed data does not match", c)
		}
		buf.Destroy()
	}
}

func TestOpenRejectsShortCiphertext(t *testing.T) {
	for _, ct := range [][]byte{{}, {0x01, 0x02}, make([]byte, OverheadFor(CipherAES256GCMSIV))} {
		buf, err := Open(&Enclave{ciphertext: ct})
		if buf != nil || err != ErrDecryptionFailed {
			t.Errorf("expected clean failure for %d-byte input; got %v, %s", len(ct), buf, err)
		}
	}
}

func TestEnclaveDestroy(t *testing.T) {
	data := []byte("yellow submarine")
	e, err := NewEnclave(data)
	if err != nil {
		t.Fatal(err)
	}
	ct := e.ciphertext

	e.Destroy()
	for i := range ct {
		if ct[i] != 0 {
			t.Fatal("ciphertext was not wiped")
		}
	}
	if e.ciphertext != nil {
		t.Error("expected nil ciphertext after destroy")
	}
	if EnclaveSize(e) != 0 {
		t.Error("expected zero size after destroy")
	}
	if _, err := Open(e); err != ErrDecryptionFailed {
		t.Error("expected decryption failure after destroy; got", err)
	}

	e.Destroy() // idempotent, must not panic
	var nilEnclave *Enclave
	nilEnclave.Destroy() // nil receiver must not panic
}

func TestEnclaveVersionTamper(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	// Flipping the version header must break opening.
	e.ciphertext[0] ^= 0xff
	if _, err := Open(e); err != ErrDecryptionFailed {
		t.Error("expected decryption failure for tampered version; got", err)
	}
}

func TestEnclaveStaleAfterPurge(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	Purge() // rotates the session key

	if _, err := Open(e); err != ErrDecryptionFailed {
		t.Error("expected decryption failure after purge; got", err)
	}
}

func TestEnclaveADRoundTrip(t *testing.T) {
	ad := []byte("stream-0011223344556677-seq!!")
	data := []byte("yellow submarine")
	e, err := NewEnclaveAD(data, ad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, make([]byte, 16)) {
		t.Error("input was not wiped")
	}
	if EnclaveSize(e) != 16 {
		t.Error("unexpected payload size:", EnclaveSize(e))
	}
	buf, err := OpenAD(e, ad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Data(), []byte("yellow submarine")) {
		t.Error("data mismatch")
	}
	buf.Destroy()

	// Wrong associated data fails, whatever its length.
	wrong := append([]byte{}, ad...)
	wrong[0] ^= 0xff
	for i, bad := range [][]byte{wrong, ad[:10], append(ad, 0x00), nil} {
		if _, err := OpenAD(e, bad); err != ErrDecryptionFailed {
			t.Errorf("case %d: expected rejection; got %s", i, err)
		}
	}
	// Plain open refuses AD seals.
	if _, err := Open(e); err != ErrDecryptionFailed {
		t.Error("expected plain open to refuse AD seal; got", err)
	}
	// Empty payload is rejected.
	if _, err := NewEnclaveAD([]byte{}, ad); err != ErrNullEnclave {
		t.Error("expected null error; got", err)
	}
}

func TestEnclaveDataSwapRejected(t *testing.T) {
	e1, err := NewEnclave([]byte("AAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := NewEnclave([]byte("BBBBBBBBBBBBBBBB"))
	if err != nil {
		t.Fatal(err)
	}

	// Transplant e2's data seal into e1's envelope. The per-enclave data
	// keys differ, so both hybrids must fail to open.
	_, w1, d1, ok1 := splitEnclave(e1.ciphertext)
	_, w2, d2, ok2 := splitEnclave(e2.ciphertext)
	if !ok1 || !ok2 {
		t.Fatal("test enclaves did not parse")
	}
	hybrid1 := append(append([]byte{}, e1.ciphertext[:len(e1.ciphertext)-len(d1)]...), d2...)
	hybrid2 := append(append([]byte{}, e2.ciphertext[:len(e2.ciphertext)-len(d2)]...), d1...)
	_ = w1
	_ = w2

	if _, err := Open(&Enclave{ciphertext: hybrid1}); err != ErrDecryptionFailed {
		t.Error("expected decryption failure for swapped seal; got", err)
	}
	if _, err := Open(&Enclave{ciphertext: hybrid2}); err != ErrDecryptionFailed {
		t.Error("expected decryption failure for swapped seal; got", err)
	}
}
