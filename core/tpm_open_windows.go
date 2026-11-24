//go:build windows

package core

import (
	"io"

	legacytpm "github.com/marcgauthier/memarmor/internal/tpm/legacy/tpm2"
)

func openTPM() (io.ReadWriteCloser, error) {
	return legacytpm.OpenTPM()
}
