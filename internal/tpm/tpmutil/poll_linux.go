package tpmutil

import (
	"syscall"
	"time"
	"unsafe"
)

func pollRead(fd *pollFD, remaining time.Duration) (uintptr, syscall.Errno) {
	timeout := syscall.NsecToTimespec(remaining.Nanoseconds())
	n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(fd)), 1, uintptr(unsafe.Pointer(&timeout)), 0, 0, 0)
	return n, errno
}
