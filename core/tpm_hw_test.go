package core

import (
	"bytes"
	"testing"
)

// TestTPMHardwareSealRoundTrip exercises the real TPM backend. It skips
// itself on machines without accessible TPM 2.0 hardware.
func TestTPMHardwareSealRoundTrip(t *testing.T) {
	be := realTPM{}
	if !be.available() {
		t.Skip("no TPM 2.0 accessible")
	}

	for _, pcrs := range [][]int{nil, {16}} {
		secret := make([]byte, 32)
		if err := Scramble(secret); err != nil {
			t.Fatal(err)
		}
		blob, err := be.seal(secret, pcrs)
		if err != nil {
			t.Fatalf("pcrs %v: seal failed: %s", pcrs, err)
		}
		back, err := be.unseal(blob)
		if err != nil {
			t.Fatalf("pcrs %v: unseal failed: %s", pcrs, err)
		}
		if !bytes.Equal(secret, back) {
			t.Errorf("pcrs %v: round-trip mismatch", pcrs)
		}
		Wipe(secret)
		Wipe(back)

		// A corrupted blob must fail, not panic.
		bad := append([]byte{}, blob...)
		bad[len(bad)-1] ^= 0xff
		if _, err := be.unseal(bad); err == nil {
			t.Errorf("pcrs %v: expected failure on corrupt blob", pcrs)
		}
	}
}
