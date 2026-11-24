//go:build linux || darwin

package tpmutil

import (
	"fmt"
	"os"
	"runtime"
)

// pollFD matches the pollfd layout on Linux and Darwin.
type pollFD struct {
	fd      int32
	events  int16
	revents int16
}

// poll blocks until the file descriptor is ready for reading or an error occurs.
func poll(f *os.File) error {
	fd := pollFD{fd: int32(f.Fd()), events: 0x1} // POLLIN
	errno := pollRead(&fd)
	runtime.KeepAlive(f)
	if errno != 0 {
		return errno
	}

	if fd.revents != fd.events {
		return fmt.Errorf("unexpected poll Revents 0x%x", fd.revents)
	}
	return nil
}
