//go:build linux || darwin

package tpmutil

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

// pollFD matches the pollfd layout on Linux and Darwin.
type pollFD struct {
	fd      int32
	events  int16
	revents int16
}

// poll waits for the file descriptor to become readable by deadline.
func poll(f *os.File, deadline time.Time) error {
	fd := pollFD{fd: int32(f.Fd()), events: 0x1} // POLLIN
	defer runtime.KeepAlive(f)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrTimeout
		}
		n, errno := pollRead(&fd, remaining)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		if n == 0 {
			return ErrTimeout
		}
		if fd.revents != fd.events {
			return fmt.Errorf("unexpected poll Revents 0x%x", fd.revents)
		}
		return nil
	}
}
