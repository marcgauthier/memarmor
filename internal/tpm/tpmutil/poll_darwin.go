// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../../thirdparty/xsys/LICENSE.

package tpmutil

import (
	"syscall"
	"unsafe"
)

//go:linkname libcCall syscall.syscall
//go:uintptrescapes
func libcCall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, errno syscall.Errno)

//go:cgo_import_dynamic libc_poll poll "/usr/lib/libSystem.B.dylib"

var pollTrampoline uintptr

func pollRead(fd *pollFD) syscall.Errno {
	_, _, errno := libcCall(pollTrampoline, uintptr(unsafe.Pointer(fd)), 1, ^uintptr(0))
	return errno
}
