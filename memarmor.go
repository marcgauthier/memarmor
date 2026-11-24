package memarmor

import (
	"github.com/marcgauthier/memarmor/core"
)

// MemoryProtectionRequirements lists the mandatory protection settings for guarded allocations.
type MemoryProtectionRequirements = core.MemoryProtectionRequirements

// MemoryProtectionStatus records per-mapping results returned by LockedBuffer.MemoryProtection.
type MemoryProtectionStatus = core.MemoryProtectionStatus

// ErrMemoryProtection indicates that a required mapping protection could not be applied.
var ErrMemoryProtection = core.ErrMemoryProtection

// RequireMemoryProtection sets the process-wide policy for guarded memory.
// It verifies the requirements before applying them. A zero value restores
// best-effort mode. Call it outside WithBytes callbacks.
func RequireMemoryProtection(required MemoryProtectionRequirements) error {
	return core.RequireMemoryProtection(required)
}

// CoreDumpLimitError reports the result of setting the process core dump size
// limit during initialization. Kernel crash collectors can have separate rules.
func CoreDumpLimitError() error { return core.CoreDumpLimitError() }

/* Enhancement: check for low memory locking limit and print warning?*/

/*
Cipher selects the authenticated cipher used to seal enclaves.

Ciphertext is self-describing, so enclaves sealed with either cipher always
open correctly no matter the current default.
*/
type Cipher = core.Cipher

const (
	// CipherXSalsa20Poly1305 is XSalsa20-Poly1305 with a 192-bit random
	// nonce. This is the default.
	CipherXSalsa20Poly1305 = core.CipherXSalsa20Poly1305
	// CipherAES256GCMSIV is AES-256-GCM-SIV (RFC 8452) with a 96-bit
	// random nonce.
	CipherAES256GCMSIV = core.CipherAES256GCMSIV
)

/*
SetCipher selects the cipher used by NewEnclave and Seal. It panics on an
unknown cipher.
*/
func SetCipher(c Cipher) {
	core.SetDefaultCipher(c)
}

/*
GetCipher returns the cipher currently used by NewEnclave and Seal.
*/
func GetCipher() Cipher {
	return core.DefaultCipher()
}

// CipherAvailable reports whether the selected cipher can run on this host.
func CipherAvailable(c Cipher) bool { return core.CipherAvailable(c) }

/*
TPMState describes what is protecting the current session key.
*/
type TPMState = core.TPMState

// ErrTPMTimeout indicates that a TPM operation exceeded its time budget.
var ErrTPMTimeout = core.ErrTPMTimeout

const (
	// TPMUnavailable means no TPM 2.0 is reachable.
	TPMUnavailable = core.TPMUnavailable
	// TPMUnused means a TPM is reachable but the current key is not sealed to it.
	TPMUnused = core.TPMUnused
	// TPMSealed means the current session key is additionally sealed to the TPM.
	TPMSealed = core.TPMSealed
	// TPMLocked means the session key was evicted from RAM and only the TPM-sealed copy remains.
	TPMLocked = core.TPMLocked
)

/*
TPMStatus reports what is protecting the current session key.
*/
func TPMStatus() TPMState {
	return core.TPMStatus()
}

/*
SetTPMSealPolicy selects PCRs bound into TPM seals of the session key. A
nonempty selection requires the TPM for future sessions. With a live key,
it returns an error if the new seal cannot be verified. It panics on a PCR
index outside 0–23.
*/
func SetTPMSealPolicy(pcrs []int) error {
	return core.SetTPMSealPolicy(pcrs)
}

/*
LockSessionKey evicts the session key from RAM, keeping only the TPM-sealed
copy. While locked, sealing and opening enclaves fail until UnlockSessionKey
restores the key.
*/
func LockSessionKey() error {
	return core.LockSessionKey()
}

/*
UnlockSessionKey restores a locked session key from its TPM seal.
*/
func UnlockSessionKey() error {
	return core.UnlockSessionKey()
}

/*
ScrambleBytes overwrites an arbitrary buffer with cryptographically-secure random bytes.
*/
func ScrambleBytes(buf []byte) {
	if err := core.Scramble(buf); err != nil {
		core.Panic(err)
	}
}

/*
WipeBytes overwrites an arbitrary buffer with zeroes.
*/
func WipeBytes(buf []byte) {
	core.Wipe(buf)
}

/*
Purge resets the session key to a fresh value and destroys all existing LockedBuffers. Existing Enclave objects will no longer be decryptable.
*/
func Purge() {
	core.Purge()
}

/*
SafePanic wipes all it can before calling panic(v).
*/
func SafePanic(v any) {
	core.Panic(v)
}

/*
SafeExit destroys everything sensitive before exiting with a specified status code.
*/
func SafeExit(c int) {
	core.Exit(c)
}
