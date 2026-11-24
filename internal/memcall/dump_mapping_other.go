//go:build !linux && !freebsd && !openbsd

package memcall

import "errors"

// ExcludeFromCoreDumps reports that this backend has no per-mapping exclusion.
func ExcludeFromCoreDumps(_ []byte) error { return errors.ErrUnsupported }
