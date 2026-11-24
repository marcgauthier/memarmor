//go:build freebsd || openbsd

package memcall

// ExcludeFromCoreDumps reports success for mappings created by Alloc, which
// applies MAP_NOCORE on FreeBSD and MAP_CONCEAL on OpenBSD.
func ExcludeFromCoreDumps(_ []byte) error { return nil }
