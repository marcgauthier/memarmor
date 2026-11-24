package tpmutil

import (
	"syscall"
	"unsafe"
)

func pollRead(fd *pollFD) syscall.Errno {
	// A nil timespec makes ppoll wait indefinitely.
	_, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(fd)), 1, 0, 0, 0, 0)
	return errno
}
