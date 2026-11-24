package memwipe

import "unsafe"

//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
//go:noescape
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

// Bytes clears b with a runtime call that the compiler retains even if the
// buffer has no subsequent reads.
func Bytes(b []byte) {
	if len(b) != 0 {
		memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)))
	}
}
