package core

import (
	"bytes"
	"testing"
)

// TestTPMHardwareSealRoundTrip exercises the real TPM backend. It skips
// itself on machines without accessible TPM 2.0 hardware.
func TestTPMHardwareSealRoundTrip(t *testing.T) {
	be := realTPM{}
	if err := be.probe(); err != nil {
		t.Skipf("no TPM 2.0 accessible: %v", err)
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
		back := make([]byte, len(secret))
		if err := be.unseal(blob, back); err != nil {
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
		if err := be.unseal(bad, back); err == nil {
			t.Errorf("pcrs %v: expected failure on corrupt blob", pcrs)
		}
	}
}
