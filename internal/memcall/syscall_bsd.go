//go:build freebsd || netbsd

package memcall

import "syscall"

func mlock(b []byte) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(_getStartPtr(b)), uintptr(len(b)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func munlock(b []byte) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MUNLOCK, uintptr(_getStartPtr(b)), uintptr(len(b)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func mprotect(b []byte, prot int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, uintptr(_getStartPtr(b)), uintptr(len(b)), uintptr(prot))
	if errno != 0 {
		return errno
	}
	return nil
}
