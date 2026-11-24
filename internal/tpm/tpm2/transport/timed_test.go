package transport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marcgauthier/memarmor/internal/tpm/tpmutil"
)

func TestPlatformTimeoutReleasesCaller(t *testing.T) {
	device, peer := net.Pipe()
	defer peer.Close()
	defer device.Close()
	tpm, err := OpenWithTimeout(func() (io.ReadWriteCloser, error) { return device, nil }, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	read := make(chan error, 1)
	go func() {
		packet := make([]byte, 4)
		_, err := io.ReadFull(peer, packet)
		read <- err
		// Leave the pipe open while the caller waits for a response.
	}()
	_, err = tpm.Send([]byte("test"))
	if !errors.Is(err, tpmutil.ErrTimeout) {
		t.Fatalf("expected TPM timeout, got %v", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}

	var reopened atomic.Bool
	_, err = OpenWithTimeout(func() (io.ReadWriteCloser, error) {
		reopened.Store(true)
		return nil, errors.New("device is still busy")
	}, 25*time.Millisecond)
	if !errors.Is(err, tpmutil.ErrTimeout) || reopened.Load() {
		t.Fatalf("stalled I/O should retain the only worker slot: %v", err)
	}

	// Let the blocked worker finish and release its connection.
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tpm.(*timedTPM).done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish after the device released it")
	}
}
