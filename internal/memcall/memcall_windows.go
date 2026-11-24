//go:build windows

package memcall

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc   = kernel32.NewProc("VirtualAlloc")
	virtualFree    = kernel32.NewProc("VirtualFree")
	virtualProtect = kernel32.NewProc("VirtualProtect")
)

// Lock is a wrapper for syscall.VirtualLock()
func Lock(b []byte) error {
	if err := syscall.VirtualLock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not acquire lock on %p, limit reached? [Err: %s]", _getStartPtr(b), err)
	}

	return nil
}

// Unlock is a wrapper for syscall.VirtualUnlock()
func Unlock(b []byte) error {
	if err := syscall.VirtualUnlock(uintptr(_getStartPtr(b)), uintptr(len(b))); err != nil {
		return fmt.Errorf("<memcall> could not free lock on %p [Err: %s]", _getStartPtr(b), err)
	}

	return nil
}

// Alloc allocates a byte slice of length n and returns it.
func Alloc(n int) ([]byte, error) {
	// Allocate the memory.
	ptr, _, err := virtualAlloc.Call(0, uintptr(n), 0x1000|0x2000, 0x4)
	if ptr == 0 {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}

	// Convert this pointer to a slice.
	b := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n)

	// Wipe it just in case there is some remnant data.
	wipe(b)

	// Return the allocated memory.
	return b, nil
}

// Free deallocates the byte slice specified.
func Free(b []byte) error {
	// Make the memory region readable and writable.
	if err := Protect(b, ReadWrite()); err != nil {
		return err
	}

	// Wipe the memory region in case of remnant data.
	wipe(b)

	// Free the memory back to the kernel.
	if ok, _, err := virtualFree.Call(uintptr(_getStartPtr(b)), 0, 0x8000); ok == 0 {
		return fmt.Errorf("<memcall> could not deallocate %p [Err: %s]", _getStartPtr(b), err)
	}

	return nil
}

// Protect modifies the memory protection flags for a specified byte slice.
func Protect(b []byte, mpf MemoryProtectionFlag) error {
	var prot int
	if mpf.flag == ReadWrite().flag {
		prot = 0x4 // PAGE_READWRITE
	} else if mpf.flag == ReadOnly().flag {
		prot = 0x2 // PAGE_READ
	} else if mpf.flag == NoAccess().flag {
		prot = 0x1 // PAGE_NOACCESS
	} else {
		return errors.New(ErrInvalidFlag)
	}

	var oldProtect uint32
	if ok, _, err := virtualProtect.Call(uintptr(_getStartPtr(b)), uintptr(len(b)), uintptr(prot), uintptr(unsafe.Pointer(&oldProtect))); ok == 0 {
		return fmt.Errorf("<memcall> could not set %d on %p [Err: %s]", prot, _getStartPtr(b), err)
	}

	return nil
}

// DisableCoreDumps is included for compatibility reasons. On windows it is a no-op function.
func DisableCoreDumps() error { return nil }
