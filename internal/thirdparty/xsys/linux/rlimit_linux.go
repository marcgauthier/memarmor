// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../LICENSE.

package linux

import (
	"syscall"
	"unsafe"
)

// Rlimit matches Linux's 64-bit prlimit64 structure on every architecture.
type Rlimit struct {
	Cur uint64
	Max uint64
}

// Prlimit reads or changes the specified process resource limit.
func Prlimit(pid, resource int, limit, old *Rlimit) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(resource), uintptr(unsafe.Pointer(limit)), uintptr(unsafe.Pointer(old)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
