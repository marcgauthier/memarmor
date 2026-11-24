package core

import (
	"github.com/marcgauthier/memarmor/internal/memcall"
)

func init() {
	memcall.DisableCoreDumps()
}
