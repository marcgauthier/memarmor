<p align="center">
  <img src="icon.png" width="256" alt="memarmor logo" />
</p>

<details align="center">
<summary><sub>Icon credit</sub></summary>
<p><sub>The Go gopher was designed by Renée French and is used under CC-BY 4.0. See <a href="https://go.dev/blog/gopher">the Go Gopher</a>.</sub></p>
</details>

---

memarmor is a security-hardened memory-protection library for Go, derived
from [memguard](https://github.com/awnumar/memguard). It keeps secrets
encrypted and guarded while they sit in process memory, and assumes a
stronger threat model than upstream: heap hygiene, hardware-backed keys,
and authenticated container integrity.

## Quick start

```go
package main

import (
	"fmt"

	"github.com/marcgauthier/memarmor"
)

func main() {
	// Wipe everything on Ctrl-C / SIGTERM.
	memarmor.CatchTermination()
	defer memarmor.Purge()

	// Optional: bind TPM seals to the measured boot state (PCR 7).
	// Without this, seals are still bound to the TPM hardware.
	memarmor.SetTPMSealPolicy([]int{7})

	// Seal a secret string; the input is wiped.
	secret := memarmor.NewEnclave([]byte("s3cr3t-token"))
	defer secret.Destroy()

	// Seal raw bytes under AES-256-GCM-SIV explicitly.
	buf := memarmor.NewEnclaveWithCipher([]byte{0x01, 0x02}, memarmor.CipherAES256GCMSIV)
	defer buf.Destroy()

	// Open when needed, destroy right after use.
	b, err := secret.Open()
	if err != nil {
		panic(err)
	}
	fmt.Println("token:", b.String())
	b.Destroy()

	// Evict the session key from RAM between uses (needs a TPM seal).
	if memarmor.TPMStatus() == memarmor.TPMSealed {
		_ = memarmor.LockSessionKey()
		// ... key is out of RAM here ...
		_ = memarmor.UnlockSessionKey()
	}
}
```

## Status

Implemented and verified: the full test suite passes with `-race`, plus
`go vet`, `gofmt`, benchmarks, and cross-compiles for Windows, macOS, and
FreeBSD. The TPM seal backend is covered by backend tests and a
hardware-gated integration test that runs where a TPM 2.0 is accessible.

## Features

* Choice of authenticated cipher for sealed data: XSalsa20-Poly1305
  (default) or AES-256-GCM-SIV (RFC 8452). Ciphertext is self-describing,
  so either kind always opens.
* TPM 2.0 integration: the session key is sealed to the platform TPM when
  one is available, with optional PCR policy binding, and can be locked
  (evicted from RAM) and unlocked on demand.
* Per-enclave data keys: every sealed container uses a unique data key
  wrapped by the versioned session key, isolating nonces across enclaves.
* Authenticated streams: chunks are bound to their stream and position,
  and closing a stream commits a length readers use to detect truncation.
* Memory hygiene: runtime-guaranteed wipes, in-place decryption with no
  heap plaintext copies, stack-only intermediate digests, and explicit
  destruction of ciphertext containers.
* Safer API surface: typed views return copies instead of aliasing locked
  memory, copies fail loudly on overflow, and resource exhaustion returns
  errors instead of panicking.
* No external Go modules. The repository includes the crypto, syscall,
  and TPM code it needs.

## Relation to memguard

memarmor started from memguard and keeps its core architecture of locked
buffers, sealed enclaves, guard pages, canaries, and session purging. All
memguard license and attribution details are kept in
[THIRD-PARTY-LICENSE](THIRD-PARTY-LICENSE).

## Acknowledgments

Built with implementation assistance from OpenAI Codex and Meta Muse.

## License

Copyright 2026 Marc Gauthier.

memarmor is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) for the full text.
