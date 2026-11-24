//go:build linux

package core

import (
	"golang.org/x/sys/unix"
)

// wipeOnFork asks the kernel to zero the mapping in any forked child, so
// secrets never leak across fork. Best effort: old kernels ignore it.
func wipeOnFork(b []byte) {
	_ = unix.Madvise(b, unix.MADV_WIPEONFORK)
}
