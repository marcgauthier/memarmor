//go:build linux

package core

import "syscall"

const madvWipeOnFork = 18 // Linux MADV_WIPEONFORK.

// wipeOnFork asks the kernel to zero the mapping in any forked child.
func wipeOnFork(b []byte) error { return syscall.Madvise(b, madvWipeOnFork) }
