//go:build !linux

package core

import "errors"

func wipeOnFork(_ []byte) error { return errors.ErrUnsupported }
