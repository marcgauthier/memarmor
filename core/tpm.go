package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	legacytpm "github.com/marcgauthier/memarmor/internal/tpm/legacy/tpm2"
	"github.com/marcgauthier/memarmor/internal/tpm/tpmutil"
)

// tpmBackend seals small secrets to the platform TPM.
type tpmBackend interface {
	// available reports whether a TPM 2.0 can be reached.
	available() bool
	// seal binds data to the TPM under the given PCR policy (empty means none).
	seal(data []byte, pcrs []int) (blob []byte, err error)
	// unseal recovers data sealed by seal.
	unseal(blob []byte) ([]byte, error)
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
)

// TPMStatus reports what is protecting the current session key.
func TPMStatus() TPMState {
	keyMtx.Lock()
	defer keyMtx.Unlock()
	return tpmState
}

// SetTPMSealPolicy selects the PCRs bound into TPM seals of the session key.
// An empty list seals without a PCR policy. The policy applies at once: the
// live key is re-sealed immediately when a TPM is reachable, otherwise the
// policy waits for the next seal. It panics on an invalid PCR index.
//
// A PCR policy binds unsealing to the platform's measured boot state. If the
// firmware or boot chain changes, the sealed key no longer unseals, so choose
// PCRs that match your update policy.
func SetTPMSealPolicy(pcrs []int) {
	for _, p := range pcrs {
		if p < 0 || p > 23 {
			panic("<memarmor::core> invalid PCR index")
		}
	}
	keyMtx.Lock()
	defer keyMtx.Unlock()
	sealPCRs = append([]int(nil), pcrs...)
	if !keyLocked && !key.Destroyed() && tpm.available() {
		resealSessionKeyLocked()
	}
}

// LockSessionKey evicts the session key from RAM, keeping only the
// TPM-sealed copy. While locked, sealing and opening enclaves fail with
// ErrSessionLocked until UnlockSessionKey restores the key; already-open
// LockedBuffers are unaffected. Locking is idempotent. It refuses with
// ErrNoSealedKey when no TPM seal exists, since that would lose the key.
func LockSessionKey() error {
	keyMtx.Lock()
	if keyLocked {
		keyMtx.Unlock()
		return nil
	}
	if sealedKey == nil {
		keyMtx.Unlock()
		return ErrNoSealedKey
	}
	if err := key.Destroy(); err != nil {
		// Destruction failed; fall back to a full purge and report it.
		keyMtx.Unlock()
		Purge()
		return err
	}
	keyLocked = true
	tpmState = TPMLocked
	keyMtx.Unlock()
	return nil
}

// UnlockSessionKey restores a locked session key from its TPM seal. The key
// value and version are preserved, so enclaves sealed before locking open
// again. It fails while the TPM refuses to unseal (for example when a PCR
// policy is no longer satisfied) and the session stays locked.
func UnlockSessionKey() error {
	keyMtx.Lock()
	defer keyMtx.Unlock()
	if !keyLocked {
		return nil
	}
	if sealedKey == nil {
		return ErrNoSealedKey
	}
	raw, err := tpm.unseal(sealedKey)
	if err != nil {
		return err
	}
	if len(raw) != 32 {
		Wipe(raw)
		return ErrDecryptionFailed
	}
	c, err := NewCoffer()
	if err != nil {
		Wipe(raw)
		return err
	}
	if err := c.InitValue(raw); err != nil {
		Wipe(raw)
		c.Destroy()
		return err
	}
	Wipe(raw)
	key = c
	keyLocked = false
	tpmState = TPMSealed
	return nil
}

// resealSessionKeyLocked seals the live session key to the TPM under the
// current PCR policy. The caller must hold keyMtx. A previous seal is kept
// when the fresh seal fails.
func resealSessionKeyLocked() {
	if keyLocked || key.Destroyed() {
		return
	}
	v, err := key.View()
	if err != nil {
		tpmState = TPMUnused
		return
	}
	blob, err := tpm.seal(v.Data(), sealPCRs)
	v.Destroy()
	if err != nil {
		tpmState = TPMUnused
		return
	}
	sealedKey = blob
	tpmState = TPMSealed
}

var tpmEnvelopeMagic = []byte("MTP1")

// packSealedEnvelope frames a TPM-sealed object with its PCR policy.
func packSealedEnvelope(pcrs []int, digest, pub, priv []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(tpmEnvelopeMagic)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(pcrs)))
	for _, p := range pcrs {
		_ = binary.Write(buf, binary.BigEndian, uint16(p))
	}
	_ = binary.Write(buf, binary.BigEndian, uint16(len(digest)))
	buf.Write(digest)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(pub)))
	buf.Write(pub)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(priv)))
	buf.Write(priv)
	return buf.Bytes()
}

// unpackSealedEnvelope parses a sealed envelope strictly, rejecting trailing
// bytes and absurd sizes.
func unpackSealedEnvelope(blob []byte) (pcrs []int, digest, pub, priv []byte, err error) {
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
	if err := binary.Read(r, binary.BigEndian, &dn); err != nil || dn > 64 {
		return fail()
	}
	digest = make([]byte, dn)
	if _, err := io.ReadFull(r, digest); err != nil {
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
	return pcrs, digest, pub, priv, nil
}

// realTPM seals through the platform TPM 2.0. A transient storage primary is
// recreated per operation, so no persistent TPM handles are consumed.
type realTPM struct{}

func (realTPM) available() bool {
	rw, err := openTPM()
	if err != nil {
		return false
	}
	rw.Close()
	return true
}

func (realTPM) seal(data []byte, pcrs []int) ([]byte, error) {
	rw, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	srk, err := createEphemeralSRK(rw)
	if err != nil {
		return nil, err
	}
	defer legacytpm.FlushContext(rw, srk)

	var digest []byte
	if len(pcrs) > 0 {
		if digest, err = trialPCRDigest(rw, pcrs); err != nil {
			return nil, err
		}
	}

	var priv, pub []byte
	if len(pcrs) > 0 {
		sealed := legacytpm.Public{
			Type:       legacytpm.AlgKeyedHash,
			NameAlg:    legacytpm.AlgSHA256,
			Attributes: legacytpm.FlagFixedTPM | legacytpm.FlagFixedParent | legacytpm.FlagAdminWithPolicy,
			AuthPolicy: tpmutil.U16Bytes(digest),
		}
		priv, pub, _, _, _, err = legacytpm.CreateKeyWithSensitive(rw, srk, legacytpm.PCRSelection{}, "", "", sealed, data)
	} else {
		priv, pub, err = legacytpm.Seal(rw, srk, "", "", nil, data)
	}
	if err != nil {
		return nil, err
	}
	return packSealedEnvelope(pcrs, digest, pub, priv), nil
}

func (realTPM) unseal(blob []byte) ([]byte, error) {
	pcrs, digest, pub, priv, err := unpackSealedEnvelope(blob)
	if err != nil {
		return nil, err
	}
	rw, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	srk, err := createEphemeralSRK(rw)
	if err != nil {
		return nil, err
	}
	defer legacytpm.FlushContext(rw, srk)

	h, _, err := legacytpm.Load(rw, srk, "", pub, priv)
	if err != nil {
		return nil, err
	}
	defer legacytpm.FlushContext(rw, h)

	if len(pcrs) == 0 {
		return legacytpm.Unseal(rw, h, "")
	}
	sess, _, err := legacytpm.StartAuthSession(rw, legacytpm.HandleNull, legacytpm.HandleNull, nil, nil, legacytpm.SessionPolicy, legacytpm.AlgNull, legacytpm.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer legacytpm.FlushContext(rw, sess)
	sel := legacytpm.PCRSelection{Hash: legacytpm.AlgSHA256, PCRs: pcrs}
	if err := legacytpm.PolicyPCR(rw, sess, digest, sel); err != nil {
		return nil, err
	}
	return legacytpm.UnsealWithSession(rw, sess, h, "")
}

// createEphemeralSRK recreates the standard RSA storage primary. Primaries
// are deterministic, so every call yields the same key without consuming a
// persistent TPM handle. It assumes an empty owner hierarchy password.
func createEphemeralSRK(rw io.ReadWriter) (tpmutil.Handle, error) {
	tmpl := legacytpm.Public{
		Type:       legacytpm.AlgRSA,
		NameAlg:    legacytpm.AlgSHA256,
		Attributes: legacytpm.FlagStorageDefault,
		RSAParameters: &legacytpm.RSAParams{
			Symmetric: &legacytpm.SymScheme{Alg: legacytpm.AlgAES, KeyBits: 128, Mode: legacytpm.AlgCFB},
			KeyBits:   2048,
		},
	}
	h, _, err := legacytpm.CreatePrimary(rw, legacytpm.HandleOwner, legacytpm.PCRSelection{}, "", "", tmpl)
	return h, err
}

// trialPCRDigest computes the policy digest for the current values of the
// given PCRs without authorizing anything.
func trialPCRDigest(rw io.ReadWriter, pcrs []int) ([]byte, error) {
	sess, _, err := legacytpm.StartAuthSession(rw, legacytpm.HandleNull, legacytpm.HandleNull, nil, nil, legacytpm.SessionTrial, legacytpm.AlgNull, legacytpm.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer legacytpm.FlushContext(rw, sess)
	sel := legacytpm.PCRSelection{Hash: legacytpm.AlgSHA256, PCRs: pcrs}
	if err := legacytpm.PolicyPCR(rw, sess, nil, sel); err != nil {
		return nil, err
	}
	return legacytpm.PolicyGetDigest(rw, sess)
}
