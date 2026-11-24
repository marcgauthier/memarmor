# Vendored go-tpm subset

Source: `github.com/google/go-tpm` at `v0.9.8` (Apache License 2.0, see
`LICENSE` in this directory).

Included packages (non-test files only):

- `tpm2` — TPM 2.0 client and commands
- `tpm2/transport` — command transport helpers
- `tpmutil` — TPM device handles (Linux device nodes, Windows TBS)
- `tpmutil/tbs` — Windows TBS backend
- `legacy/tpm2` — legacy helpers still used by `tpm2`

Excluded: `tpm` (TPM 1.2), examples, all test files and test-only helpers
(including the simulator, which needs `go-tpm-tools`).

Import paths were rewritten from `github.com/google/go-tpm/` to
`github.com/awnumar/memguard/internal/tpm/`. No functional changes.
