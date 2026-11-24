//go:build (amd64 || arm64) && !purego

package gcmsiv

import (
	"runtime"

	"github.com/marcgauthier/memarmor/internal/thirdparty/xsys/cpu"
)

// Available reports whether this process can use the hardware AES backend.
func Available() bool {
	switch runtime.GOARCH {
	case "amd64":
		return cpu.X86.HasAES && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	case "arm64":
		return cpu.ARM64.HasAES
	default:
		return false
	}
}

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)
