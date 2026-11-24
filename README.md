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
	"github.com/marcgauthier/memarmor"
)

func main() {
	// Wipe everything on Ctrl-C / SIGTERM.
	memarmor.CatchTermination()
	defer memarmor.Purge()

	secret := memarmor.NewEnclaveRandom(32)
	if secret == nil {
		panic("could not create secret")
	}
	defer secret.Destroy()

	b, err := secret.Open()
	if err != nil {
		panic(err)
	}
	b.WithBytes(func(key []byte) {
		// Use key here. The slice is borrowed for this callback.
	})
	b.Destroy()

	if memarmor.TPMStatus() == memarmor.TPMSealed {
		if err := memarmor.LockSessionKey(); err != nil {
			panic(err)
		}
		// The session key can be restored on demand.
		if err := memarmor.UnlockSessionKey(); err != nil {
			panic(err)
		}
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
  (default) or AES-256-GCM-SIV (RFC 8452). Check `CipherAvailable` before
  selecting AES-256-GCM-SIV. It requires the hardware AES backend on amd64
  or arm64 and is unavailable with the `purego` build tag.
* TPM 2.0 integration: the session key is sealed to the platform TPM when
  one is available. The TPM derives a wrapping key and returns it through an
  encrypted session. Locking verifies the seal before evicting the live key.
  Check the error from `SetTPMSealPolicy` when requiring PCR binding. A
  nonempty policy requires a working TPM when the next session starts.
  Each platform TPM connection has a 30-second budget. Use
  `errors.Is(err, memarmor.ErrTPMTimeout)` to identify a timeout.
* Per-enclave data keys: every sealed container uses a unique data key
  wrapped by the versioned session key, isolating nonces across enclaves.
* Authenticated streams: chunks are bound to their stream and position,
  and closing a stream commits a length readers use to detect truncation.
  `Write` preserves the input and `WriteAndWipe` explicitly consumes it.
* Memory hygiene: enclave data keys, associated-data staging, and
  AES-GCM-SIV key schedules use guarded memory. Decryption writes into
  guarded buffers. Purge and exit wait for scoped `WithBytes` callbacks.
  Synchronize raw aliases from `Bytes` and `Reader` with purge and
  destruction. Formatting a `LockedBuffer` via `String` or `GoString`
  produces redacted text.
* Safer API surface: typed views return copies instead of aliasing locked
  memory, copies fail loudly on overflow, and resource exhaustion returns
  errors instead of panicking.
* No external Go modules. The repository includes the crypto, syscall,
  and TPM code it needs.

Use `RequireMemoryProtection` before handling secrets if your deployment
requires per-mapping dump exclusion or fork wiping. Check its error and
abort startup if a required protection is unavailable. Inspect
`buf.MemoryProtection()` for the outcome on a particular mapping.
`CoreDumpLimitError` reports the startup process-limit call. It does not
report crash collector policy or cover copies created by the application.

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
