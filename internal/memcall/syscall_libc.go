// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../thirdparty/xsys/LICENSE.

//go:build aix || solaris

package memcall

import "unsafe"

//go:linkname libcMlock libc_mlock
//go:linkname libcMunlock libc_munlock
//go:linkname libcMprotect libc_mprotect
var libcMlock, libcMunlock, libcMprotect uintptr

func callMemory(fn *uintptr, nargs uintptr, b []byte, arg uintptr) error {
	_, _, errno := libcCall(uintptr(unsafe.Pointer(fn)), nargs, uintptr(_getStartPtr(b)), uintptr(len(b)), arg, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func mlock(b []byte) error              { return callMemory(&libcMlock, 2, b, 0) }
func munlock(b []byte) error            { return callMemory(&libcMunlock, 2, b, 0) }
func mprotect(b []byte, prot int) error { return callMemory(&libcMprotect, 3, b, uintptr(prot)) }
