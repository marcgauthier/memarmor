//go:build !windows

package memarmor

import (
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestCatchSignal(t *testing.T) {
	// If we're within the testing subprocess, run test.
	if os.Getenv("WITHIN_SUBPROCESS") == "1" {
		// Start a listener object
		listener, err := net.Listen("tcp", "127.0.0.1:")
		if err != nil {
			SafePanic(err)
		}
		defer listener.Close()

		// Spawn a handler to catch interrupts
		CatchSignal(func(s os.Signal) {
			listener.Close()
		})

		// Grab a handle on the running process
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Error(err)
		}

		// Send it an interrupt signal
		if err := process.Signal(os.Interrupt); err != nil {
			t.Error(err)
		}
	}

	// Construct the subprocess with its initial state
	cmd := exec.Command(os.Args[0], "-test.run=TestCatchSignal")
	cmd.Env = append(os.Environ(), "WITHIN_SUBPROCESS=1")

	// Execute the subprocess and inspect its exit code
	err := cmd.Run().(*exec.ExitError)
	if err.ExitCode() != 1 {
		// if exit code is -1 it was likely killed by the signal
		t.Error("Wanted exit code 1, got", err.ExitCode(), "err:", err)
	}

	// Todo: catch this violation (segfault)
	//
	// b := NewBuffer(32)
	// bA := (*[64]byte)(unsafe.Pointer(&b.Bytes()[0]))
	// bA[42] = 0x69 // write to guard page region
}

func TestCatchInterrupt(t *testing.T) {
	if os.Getenv("WITHIN_SUBPROCESS") == "1" {
		// Start the interrupt handler
		CatchInterrupt()

		// Grab a handle on the running process
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Error(err)
		}

		// Send it an interrupt signal
		if err := process.Signal(os.Interrupt); err != nil {
			t.Error(err)
		}
	}

	// Construct the subprocess with its initial state
	cmd := exec.Command(os.Args[0], "-test.run=TestCatchInterrupt")
	cmd.Env = append(os.Environ(), "WITHIN_SUBPROCESS=1")

	// Execute the subprocess and inspect its exit code
	err := cmd.Run().(*exec.ExitError)
	if err.ExitCode() != 1 {
		// if exit code is -1 it was likely killed by the signal
		t.Error("Wanted exit code 1, got", err.ExitCode(), "err:", err)
	}
}

func TestCatchTermination(t *testing.T) {
	if os.Getenv("WITHIN_SUBPROCESS") == "1" {
		// Start the termination handler
		CatchTermination()

		// Grab a handle on the running process
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Error(err)
		}

		// Send it a terminate signal
		if err := process.Signal(syscall.SIGTERM); err != nil {
			t.Error(err)
		}
	}

	// Construct the subprocess with its initial state
	cmd := exec.Command(os.Args[0], "-test.run=TestCatchTermination")
	cmd.Env = append(os.Environ(), "WITHIN_SUBPROCESS=1")

	// Execute the subprocess and inspect its exit code
	err := cmd.Run().(*exec.ExitError)
	if err.ExitCode() != 1 {
		t.Error("Wanted exit code 1, got", err.ExitCode(), "err:", err)
	}
}

func TestCatchSignalPreservesHandlers(t *testing.T) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGURG)
	defer signal.Stop(ch)

	// Registering a memguard handler must not clobber existing ones.
	CatchSignal(func(os.Signal) {}, os.Interrupt)

	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.SIGURG); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("previously registered channel stopped receiving")
	}
}
