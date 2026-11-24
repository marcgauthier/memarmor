package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// fakeTPM is a test backend that frames sealed data without hardware.
type fakeTPM struct {
	avail        bool
	failSeal     bool
	failUnseal   bool
	sealed       [][]byte
	sealedPCRs   [][]int
	sealedPolicy [][]byte
}

func (f *fakeTPM) available() bool { return f.avail }

func (f *fakeTPM) seal(data []byte, pcrs []int) ([]byte, error) {
	if !f.avail || f.failSeal {
		return nil, errors.New("fakeTPM: seal unavailable")
	}
	f.sealed = append(f.sealed, append([]byte{}, data...))
	f.sealedPCRs = append(f.sealedPCRs, append([]int(nil), pcrs...))
	buf := new(bytes.Buffer)
	buf.Write([]byte("FAKE"))
	_ = binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
	return buf.Bytes(), nil
}

func (f *fakeTPM) unseal(blob []byte) ([]byte, error) {
	if !f.avail || f.failUnseal {
		return nil, errors.New("fakeTPM: unseal unavailable")
	}
	if len(blob) < 6 || string(blob[:4]) != "FAKE" {
		return nil, ErrDecryptionFailed
	}
	n := int(binary.BigEndian.Uint16(blob[4:6]))
	if len(blob) != 6+n {
		return nil, ErrDecryptionFailed
	}
	return append([]byte{}, blob[6:]...), nil
}

// useFakeTPM installs a fake backend with a fresh session for one test.
func useFakeTPM(t *testing.T, f *fakeTPM) {
	t.Helper()
	old := tpm
	tpm = f
	Purge()
	SetTPMSealPolicy(nil)
	t.Cleanup(func() {
		Purge()
		SetTPMSealPolicy(nil)
		tpm = old
	})
}

func TestTPMAutoSeal(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	if _, err := NewEnclave([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if TPMStatus() != TPMSealed {
		t.Error("expected sealed state; got", TPMStatus())
	}
	if len(f.sealed) != 1 || len(f.sealed[0]) != 32 {
		t.Fatal("session key was not sealed")
	}
}

func TestTPMLockUnlock(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := LockSessionKey(); err != nil {
		t.Fatal(err)
	}
	if TPMStatus() != TPMLocked {
		t.Error("expected locked state; got", TPMStatus())
	}
	if _, err := Open(e); err != ErrSessionLocked {
		t.Error("expected locked error on open; got", err)
	}
	if _, err := NewEnclave([]byte("x")); err != ErrSessionLocked {
		t.Error("expected locked error on seal; got", err)
	}
	if err := LockSessionKey(); err != nil {
		t.Error("locking is not idempotent:", err)
	}

	if err := UnlockSessionKey(); err != nil {
		t.Fatal(err)
	}
	if TPMStatus() != TPMSealed {
		t.Error("expected sealed state; got", TPMStatus())
	}
	buf, err := Open(e)
	if err != nil {
		t.Fatal("enclave sealed before locking did not open:", err)
	}
	if !bytes.Equal(buf.Data(), []byte("yellow submarine")) {
		t.Error("data mismatch after unlock")
	}
	buf.Destroy()
	if err := UnlockSessionKey(); err != nil {
		t.Error("unlocking is not idempotent:", err)
	}
}

func TestTPMLockWithoutSeal(t *testing.T) {
	f := &fakeTPM{avail: false}
	useFakeTPM(t, f)

	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	if TPMStatus() != TPMUnavailable {
		t.Error("expected unavailable state; got", TPMStatus())
	}
	if err := LockSessionKey(); err != ErrNoSealedKey {
		t.Error("expected refusal without a seal; got", err)
	}
	// The session keeps working on its RAM key.
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	buf.Destroy()
}

func TestTPMPurgeWhileLocked(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := LockSessionKey(); err != nil {
		t.Fatal(err)
	}
	Purge()

	// The purge retired the sealed copy too: unlocking is a no-op and the
	// old enclave is dead under the fresh key.
	if TPMStatus() != TPMUnused {
		t.Error("expected unused state after purge; got", TPMStatus())
	}
	if err := UnlockSessionKey(); err != nil {
		t.Error("unlock after purge should be a no-op; got", err)
	}
	if _, err := Open(e); err != ErrDecryptionFailed {
		t.Error("expected decryption failure after purge; got", err)
	}
	// A fresh session works again.
	if _, err := NewEnclave([]byte("next")); err != nil {
		t.Error("fresh session broken:", err)
	}
}

func TestTPMSealPolicy(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	if _, err := NewEnclave([]byte("data")); err != nil {
		t.Fatal(err)
	}
	SetTPMSealPolicy([]int{7})
	if len(f.sealedPCRs) == 0 || len(f.sealedPCRs[len(f.sealedPCRs)-1]) != 1 || f.sealedPCRs[len(f.sealedPCRs)-1][0] != 7 {
		t.Error("live key was not re-sealed under the new policy")
	}

	// The policy also applies to the next session key.
	Purge()
	if _, err := NewEnclave([]byte("data")); err != nil {
		t.Fatal(err)
	}
	last := f.sealedPCRs[len(f.sealedPCRs)-1]
	if len(last) != 1 || last[0] != 7 {
		t.Error("policy did not carry to the next key")
	}

	if !panics(func() { SetTPMSealPolicy([]int{-1}) }) {
		t.Error("expected panic on negative PCR")
	}
	if !panics(func() { SetTPMSealPolicy([]int{24}) }) {
		t.Error("expected panic on PCR above 23")
	}
}

func TestTPMSealFailureDegraded(t *testing.T) {
	f := &fakeTPM{avail: true, failSeal: true}
	useFakeTPM(t, f)

	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	if TPMStatus() != TPMUnused {
		t.Error("expected degraded state; got", TPMStatus())
	}
	if err := LockSessionKey(); err != ErrNoSealedKey {
		t.Error("expected refusal without a seal; got", err)
	}
	// Baseline RAM-key operation keeps working.
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	buf.Destroy()
}

func TestTPMUnsealFailureStaysLocked(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := LockSessionKey(); err != nil {
		t.Fatal(err)
	}

	f.failUnseal = true
	if err := UnlockSessionKey(); err == nil {
		t.Fatal("expected unlock failure")
	}
	if TPMStatus() != TPMLocked {
		t.Error("session should stay locked; got", TPMStatus())
	}
	if _, err := Open(e); err != ErrSessionLocked {
		t.Error("expected locked error; got", err)
	}

	f.failUnseal = false
	if err := UnlockSessionKey(); err != nil {
		t.Fatal(err)
	}
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}
	buf.Destroy()
}

func TestTPMLockedBlocksAD(t *testing.T) {
	f := &fakeTPM{avail: true}
	useFakeTPM(t, f)

	ad := []byte("0123456789abcdef01234567")
	e, err := NewEnclaveAD([]byte("data"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if err := LockSessionKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEnclaveAD([]byte("data"), ad); err != ErrSessionLocked {
		t.Error("expected locked error on seal; got", err)
	}
	if _, err := OpenAD(e, ad); err != ErrSessionLocked {
		t.Error("expected locked error on open; got", err)
	}
	if err := UnlockSessionKey(); err != nil {
		t.Fatal(err)
	}
	buf, err := OpenAD(e, ad)
	if err != nil {
		t.Fatal(err)
	}
	buf.Destroy()
}

func TestSealedEnvelopeRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	pub := bytes.Repeat([]byte{0x01}, 64)
	priv := bytes.Repeat([]byte{0x02}, 128)

	blob := packSealedEnvelope([]int{0, 7}, digest, pub, priv)
	pcrs, d, p, v, err := unpackSealedEnvelope(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(pcrs) != 2 || pcrs[0] != 0 || pcrs[1] != 7 {
		t.Error("pcrs mismatch:", pcrs)
	}
	if !bytes.Equal(d, digest) || !bytes.Equal(p, pub) || !bytes.Equal(v, priv) {
		t.Error("envelope contents mismatch")
	}

	for i, bad := range [][]byte{
		{},
		[]byte("XXXX"),
		blob[:len(blob)-1], // truncated
		append(blob, 0x00), // trailing garbage
		append([]byte{}, blob...),
	} {
		if i == 4 {
			bad[0] ^= 0xff // broken magic
		}
		if _, _, _, _, err := unpackSealedEnvelope(bad); err != ErrDecryptionFailed {
			t.Errorf("case %d: expected rejection; got %s", i, err)
		}
	}
}
