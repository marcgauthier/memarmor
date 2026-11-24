//go:build (!amd64 && !arm64) || purego

package gcmsiv

// Available reports whether this process can use the hardware AES backend.
func Available() bool { return false }

func encryptBlockAsm(int, *uint32, *byte, *byte) {
	panic("gcmsiv: hardware AES is unavailable")
}

func expandKeyAsm(int, *byte, *uint32, *uint32) {
	panic("gcmsiv: hardware AES is unavailable")
}
