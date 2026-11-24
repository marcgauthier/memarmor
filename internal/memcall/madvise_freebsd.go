package memcall

import "syscall"

func madvise(b []byte, advice int) {
	_, _, _ = syscall.Syscall(syscall.SYS_MADVISE, uintptr(_getStartPtr(b)), uintptr(len(b)), uintptr(advice))
}
