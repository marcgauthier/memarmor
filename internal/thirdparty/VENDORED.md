# In-tree upstream sources

- `gcmsiv` comes from `github.com/marcgauthier/aes-gcm-siv` at
  `149bbf528584`. It contains the AEAD and POLYVAL implementation with
  the original license and AWS-LC attribution. Length checks use
  64-bit comparisons for builds on 32-bit architectures.
  MemArmor uses table-free POLYVAL and accepts caller-supplied guarded
  workspace for hardware AES schedules. The amd64 and arm64 AES assembly
  comes from Go 1.25.0 with decryption-only routines omitted.
- `xcrypto` contains the runtime sources for BLAKE2b, NaCl secretbox,
  Salsa20, Poly1305, and their overlap checks from `golang.org/x/crypto`
  at `v0.50.0`. Package imports were rewritten to use the in-tree copies.
  Secretbox wipes its derived keys and initial keystream block on return.
- `xsys` contains the CPU detection code from `golang.org/x/sys` at
  `v0.44.0` to retain the crypto assembly dispatch. The Windows
  bindings are checked in and the upstream generator directive was removed.
  The same release is the source for the narrow platform bindings adapted
  in `xsys/linux`, `internal/memcall`, and `internal/tpm/tpmutil`.

The Go Authors' BSD license and patent grant are included in `xcrypto`
and `xsys`.
