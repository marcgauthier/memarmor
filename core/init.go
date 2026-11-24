package core

import (
	"github.com/marcgauthier/memarmor/internal/memcall"
)

var coreDumpLimitErr = memcall.DisableCoreDumps()

// CoreDumpLimitError reports the outcome of setting the process core-dump
// size limit at initialization. It describes that call only.
func CoreDumpLimitError() error { return coreDumpLimitErr }
