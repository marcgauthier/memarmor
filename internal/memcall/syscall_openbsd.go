// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../thirdparty/xsys/LICENSE.

package memcall

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

const mapConceal = 0x8000 // OpenBSD MAP_CONCEAL.

// OpenBSD requires system calls to go through libc.
//
//go:linkname libcCall syscall.syscall
//go:uintptrescapes
func libcCall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, errno syscall.Errno)

//go:cgo_import_dynamic libc_mlock mlock "libc.so"
//go:cgo_import_dynamic libc_munlock munlock "libc.so"
//go:cgo_import_dynamic libc_mprotect mprotect "libc.so"

var mlockTrampoline, munlockTrampoline, mprotectTrampoline uintptr

func callMemory(fn uintptr, b []byte, arg uintptr) error {
	_, _, errno := libcCall(fn, uintptr(_getStartPtr(b)), uintptr(len(b)), arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func mlock(b []byte) error              { return callMemory(mlockTrampoline, b, 0) }
func munlock(b []byte) error            { return callMemory(munlockTrampoline, b, 0) }
func mprotect(b []byte, prot int) error { return callMemory(mprotectTrampoline, b, uintptr(prot)) }
