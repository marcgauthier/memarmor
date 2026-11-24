package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/marcgauthier/memarmor/internal/tpm/tpmutil"
)

// tpmBackend seals small secrets to the platform TPM.
type tpmBackend interface {
	// probe checks whether a TPM 2.0 can be reached.
	probe() error
	// seal binds data to the TPM under the given PCR policy (empty means none).
	seal(data []byte, pcrs []int) (blob []byte, err error)
	// unseal recovers data sealed by seal.
	unseal(blob, dst []byte) error
}

var tpm tpmBackend = realTPM{}

// TPMState describes what is protecting the current session key.
type TPMState int

const (
	// TPMUnavailable means no TPM 2.0 is reachable; the session key lives only in locked RAM.
	TPMUnavailable TPMState = iota
	// TPMUnused means a TPM is reachable but the current key is not sealed to it.
	TPMUnused
	// TPMSealed means the current session key is additionally sealed to the TPM.
	TPMSealed
	// TPMLocked means the session key was evicted from RAM and only the TPM-sealed copy remains.
	TPMLocked
)

func (s TPMState) String() string {
	switch s {
	case TPMUnavailable:
		return "no TPM 2.0 reachable"
	case TPMUnused:
		return "TPM reachable, session key not sealed"
	case TPMSealed:
		return "session key sealed to TPM"
	case TPMLocked:
		return "session key locked in TPM"
	default:
		return "unknown TPM state"
	}
}

var (
	// ErrSessionLocked is returned when an operation needs the session key while it is locked in the TPM.
	ErrSessionLocked = errors.New("<memarmor::core::ErrSessionLocked> session key is locked in the TPM; call UnlockSessionKey first")
	// ErrNoSealedKey is returned when locking without a TPM-sealed copy, which would lose the key.
	ErrNoSealedKey = errors.New("<memarmor::core::ErrNoSealedKey> no TPM-sealed session key exists")
	// ErrTPMPolicy indicates that the configured seal policy could not be enforced.
	ErrTPMPolicy = errors.New("<memarmor::core> TPM seal policy could not be enforced")
	// ErrTPMTimeout indicates that a TPM operation exceeded its time budget.
	ErrTPMTimeout = tpmutil.ErrTimeout
)

// TPMStatus reports what is protecting the current session key.
func TPMStatus() TPMState {
	keyMtx.Lock()
	defer keyMtx.Unlock()
	return tpmState
}

// SetTPMSealPolicy selects the PCRs for future seals. With a live key, the
// new policy takes effect only after a successful, verified seal.
// An empty selection makes TPM use optional.
func SetTPMSealPolicy(pcrs []int) error {
	pcrs = slices.Clone(pcrs)
	slices.Sort(pcrs)
	for i, p := range pcrs {
		if p < 0 || p > 23 {
			panic("<memarmor::core> invalid PCR index")
		}
		if i > 0 && p == pcrs[i-1] {
			return fmt.Errorf("%w: duplicate PCR index %d", ErrTPMPolicy, p)
		}
	}
	sessionMu.Lock()
	defer finishSessionTransition()
	keyMtx.Lock()
	defer keyMtx.Unlock()
	if keyLocked {
		return ErrSessionLocked
	}
	if key.Destroyed() {
		sealPCRs = pcrs
		return nil
	}

	// Retire the old seal even when its replacement fails.
	Wipe(sealedKey)
	sealedKey = nil
	tpmState = TPMUnused
	blob, err := sealAndVerify(key, pcrs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTPMPolicy, err)
	}
	sealedKey = blob
	sealPCRs = pcrs
	tpmState = TPMSealed
	return nil
}

// LockSessionKey waits for active enclave operations and verifies the seal
// before evicting the session key. Already-open buffers remain valid.
func LockSessionKey() error {
	sessionMu.Lock()
	defer finishSessionTransition()
	keyMtx.Lock()
	defer keyMtx.Unlock()
	if keyLocked {
		return nil
	}
	if sealedKey == nil {
		return ErrNoSealedKey
	}
	view, err := key.view()
	if err != nil {
		return err
	}
	err = verifySealedValue(view.Data(), sealedKey)
	view.discard()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTPMPolicy, err)
	}
	if err := key.Destroy(); err != nil {
		panic(err)
	}
	keyLocked = true
	tpmState = TPMLocked
	return nil
}

// UnlockSessionKey restores a locked key without advancing the key version.
// Unseal failures leave the session locked.
func UnlockSessionKey() error {
	sessionMu.Lock()
	defer finishSessionTransition()
	keyMtx.Lock()
	defer keyMtx.Unlock()
	if !keyLocked {
		return nil
	}
	if sealedKey == nil {
		return ErrNoSealedKey
	}
	raw, err := newBuffer(32)
	if err != nil {
		return err
	}
	defer raw.discard()
	if err := tpm.unseal(sealedKey, raw.Data()); err != nil {
		return err
	}
	c, err := newCoffer()
	if err != nil {
		return err
	}
	if err := c.initValue(raw.Data()); err != nil {
		_ = c.Destroy()
		return err
	}
	key = c
	keyLocked = false
	tpmState = TPMSealed
	return nil
}

func sealAndVerify(c *Coffer, pcrs []int) ([]byte, error) {
	v, err := c.view()
	if err != nil {
		return nil, err
	}
	defer v.discard()
	blob, err := tpm.seal(v.Data(), pcrs)
	if err != nil {
		return nil, err
	}
	if err := verifySealedValue(v.Data(), blob); err != nil {
		Wipe(blob)
		return nil, err
	}
	return blob, nil
}

func verifySealedValue(expected, blob []byte) error {
	raw, err := newBuffer(len(expected))
	if err != nil {
		return err
	}
	defer raw.discard()
	if err := tpm.unseal(blob, raw.Data()); err != nil {
		return err
	}
	if !Equal(raw.Data(), expected) {
		return ErrDecryptionFailed
	}
	return nil
}

var tpmEnvelopeMagic = []byte("MTP2")

// packSealedEnvelope frames a TPM-sealed object with its PCR policy.
func packSealedEnvelope(pcrs []int, wrapped, pub, priv []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(tpmEnvelopeMagic)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(pcrs)))
	for _, p := range pcrs {
		_ = binary.Write(buf, binary.BigEndian, uint16(p))
	}
	_ = binary.Write(buf, binary.BigEndian, uint16(len(wrapped)))
	buf.Write(wrapped)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(pub)))
	buf.Write(pub)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(priv)))
	buf.Write(priv)
	return buf.Bytes()
}

// unpackSealedEnvelope parses a sealed envelope strictly, rejecting trailing
// bytes and absurd sizes.
func unpackSealedEnvelope(blob []byte) (pcrs []int, wrapped, pub, priv []byte, err error) {
	fail := func() ([]int, []byte, []byte, []byte, error) {
		return nil, nil, nil, nil, ErrDecryptionFailed
	}
	r := bytes.NewReader(blob)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil || !bytes.Equal(magic, tpmEnvelopeMagic) {
		return fail()
	}
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil || n > 24 {
		return fail()
	}
	pcrs = make([]int, 0, n)
	for i := 0; i < int(n); i++ {
		var p uint16
		if err := binary.Read(r, binary.BigEndian, &p); err != nil || p > 23 {
			return fail()
		}
		pcrs = append(pcrs, int(p))
	}
	var dn uint16
	if err := binary.Read(r, binary.BigEndian, &dn); err != nil || dn > 128 {
		return fail()
	}
	wrapped = make([]byte, dn)
	if _, err := io.ReadFull(r, wrapped); err != nil {
		return fail()
	}
	var pubLen, privLen uint32
	if err := binary.Read(r, binary.BigEndian, &pubLen); err != nil || pubLen > 64*1024 {
		return fail()
	}
	pub = make([]byte, pubLen)
	if _, err := io.ReadFull(r, pub); err != nil {
		return fail()
	}
	if err := binary.Read(r, binary.BigEndian, &privLen); err != nil || privLen > 64*1024 {
		return fail()
	}
	priv = make([]byte, privLen)
	if _, err := io.ReadFull(r, priv); err != nil {
		return fail()
	}
	if r.Len() != 0 {
		return fail()
	}
	return pcrs, wrapped, pub, priv, nil
}
