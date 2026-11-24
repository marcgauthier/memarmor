//go:build linux || darwin

package tpmutil

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestPollDeadline(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := poll(reader, time.Now().Add(25*time.Millisecond)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected timeout for empty pipe, got %v", err)
	}
	if _, err := writer.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := poll(reader, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("ready pipe: %v", err)
	}
}
