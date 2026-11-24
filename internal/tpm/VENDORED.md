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
`github.com/marcgauthier/memarmor/internal/tpm/`. TPM device polling uses
in-tree platform bindings. The upstream `stringer` directive was removed
from this snapshot.

MemArmor adds a guarded destination for an authenticated and encrypted TPM
HMAC response. The reusable transport sessions wipe their key bytes when
closed.

Platform TPM connections use a bounded I/O worker and a transaction deadline.
Device readiness and retry waits also honor the deadline.
