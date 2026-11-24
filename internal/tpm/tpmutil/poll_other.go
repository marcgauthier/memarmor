//go:build !linux && !darwin

package tpmutil

import (
	"os"
	"time"
)

// Not implemented on Windows.
func poll(_ *os.File, _ time.Time) error { return nil }
