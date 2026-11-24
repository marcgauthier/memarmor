//go:build linux

package core

import "syscall"

const madvWipeOnFork = 18 // Linux MADV_WIPEONFORK.

// wipeOnFork asks the kernel to zero the mapping in any forked child, so
// secrets never leak across fork. Best effort: old kernels ignore it.
func wipeOnFork(b []byte) {
	_ = syscall.Madvise(b, madvWipeOnFork)
}
