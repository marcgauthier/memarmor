package core

import (
	"bytes"
	"testing"
	"time"
)

func TestPurgeWaitsForScopedAccess(t *testing.T) {
	b, err := NewBuffer(32)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	b.Data()[0] = 42
	entered, release, used, purged := make(chan struct{}), make(chan struct{}), make(chan byte, 1), make(chan struct{})
	defer func() {
		if release != nil {
			close(release)
		}
	}()
	go func() {
		b.WithBytes(func(data []byte) {
			close(entered)
			<-release
			used <- data[0]
		})
	}()
	<-entered
	go func() {
		Purge()
		close(purged)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		next, err := NewBuffer(1)
		if err == ErrSessionBusy {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		next.Destroy()
		if time.Now().After(deadline) {
			t.Fatal("purge never excluded new work")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if <-used != 42 {
		t.Fatal("purge changed the borrowed data before its scope ended")
	}
	release = nil
	select {
	case <-purged:
	case <-time.After(5 * time.Second):
		t.Fatal("purge did not finish")
	}
	if b.Alive() {
		t.Fatal("purge left the buffer alive")
	}
}

func TestPurge(t *testing.T) {
	// Create a bunch of things to simulate a working environment.
	enclave, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Error(err)
	}
	buffer, err := NewBuffer(32)
	if err != nil {
		t.Error(err)
	}

	oldKey, _, _ := keyAndVersion()
	Purge()
	key, _, _ := keyAndVersion()

	// Verify that the buffers list contains only the important buffers.
	buffers.RLock()
	if len(buffers.list) != 3 {
		t.Error("buffers list was not flushed", buffers.list)
	}
	for i := range buffers.list {
		if !buffers.list[i].Alive() {
			t.Error("should not have destroyed excluded buffers")
		}
	}
	if !key.right.Alive() || !key.left.Alive() || !key.rand.Alive() {
		t.Error("buffers left in list aren't the right ones")
	}
	buffers.RUnlock()

	// Verify that the buffer was destroyed.
	if buffer.alive {
		t.Error("buffer was not destroyed")
	}

	// Verify that the old key was destroyed.
	if oldKey.left.alive || oldKey.right.alive {
		t.Error("old key was not destroyed")
	}

	// Verify that the new key is not destroyed.
	if !key.left.alive || !key.right.alive {
		t.Error("current key is destroyed")
	}

	// Verify that the key changed by decrypting the Enclave.
	if _, err := Open(enclave); err != ErrDecryptionFailed {
		t.Error("expected decryption failed; got", err)
	}

	// Create a buffer with invalid canary.
	b, err := NewBuffer(32)
	if err != nil {
		t.Error(err)
	}
	Scramble(b.inner)
	b.Freeze()
	if !panics(func() {
		Purge()
	}) {
		t.Error("did not panic")
	}
	if !bytes.Equal(b.data, make([]byte, 32)) {
		t.Error("data not wiped")
	}
	buffers.remove(b)
}

func TestPanic(t *testing.T) {
	// Call Panic and check if it panics.
	if !panics(func() {
		Panic("test")
	}) {
		t.Error("did not panic")
	}
}

func panics(fn func()) (panicked bool) {
	defer func() {
		panicked = (recover() != nil)
	}()
	fn()
	return
}
