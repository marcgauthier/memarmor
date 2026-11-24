package memcall

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

//go:cgo_import_dynamic libc_mlock mlock "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_munlock munlock "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_mprotect mprotect "libc.a/shr_64.o"

//go:linkname libcCall syscall.syscall6
//go:uintptrescapes
func libcCall(fn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, errno syscall.Errno)
