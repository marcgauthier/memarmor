package gcmsiv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC8452AES256(t *testing.T) {
	if !Available() {
		t.Skip("hardware AES is unavailable")
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// RFC 8452 Appendix C.2, eight bytes of plaintext and one byte of AD.
	key := decode("0100000000000000000000000000000000000000000000000000000000000000")
	nonce := decode("030000000000000000000000")
	plaintext := decode("0200000000000000")
	ad := []byte{1}
	expected := decode("1de22967237a813291213f267e3b452f02d01ae33e4ec854")
	aead, err := New(key, new(Workspace))
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, ad)
	if !bytes.Equal(sealed, expected) {
		t.Fatalf("seal mismatch: %x", sealed)
	}
	aead, err = New(key, new(Workspace))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := aead.Open(nil, nonce, expected, ad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open mismatch: %x, %v", opened, err)
	}
}
