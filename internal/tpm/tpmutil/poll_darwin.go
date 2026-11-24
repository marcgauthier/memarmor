// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../../thirdparty/xsys/LICENSE.

package tpmutil

import (
	"syscall"
	"time"
	"unsafe"
)

//go:linkname libcCall syscall.syscall
//go:uintptrescapes
func libcCall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, errno syscall.Errno)

//go:cgo_import_dynamic libc_poll poll "/usr/lib/libSystem.B.dylib"

var pollTrampoline uintptr

func pollRead(fd *pollFD, remaining time.Duration) (uintptr, syscall.Errno) {
	millis := min((remaining-1)/time.Millisecond+1, 1<<31-1)
	n, _, errno := libcCall(pollTrampoline, uintptr(unsafe.Pointer(fd)), 1, uintptr(millis))
	return n, errno
}
