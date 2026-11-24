//go:build linux

package core

import (
	"testing"

	"github.com/marcgauthier/memarmor/internal/thirdparty/xsys/linux"
)

// TestResourceExhaustion drops the memlock limit to zero and verifies that
// allocation failures surface as errors instead of panics, and that failed
// allocations register nothing.
func TestResourceExhaustion(t *testing.T) {
	var old linux.Rlimit
	if err := linux.Prlimit(0, linux.RlimitMemlock, nil, &old); err != nil {
		t.Skipf("cannot query memlock limit: %s", err)
	}
	zero := linux.Rlimit{Cur: 0, Max: old.Max}
	if err := linux.Prlimit(0, linux.RlimitMemlock, &zero, nil); err != nil {
		t.Skipf("cannot lower memlock limit: %s", err)
	}
	defer func() {
		restore := linux.Rlimit{Cur: old.Cur, Max: old.Max}
		if err := linux.Prlimit(0, linux.RlimitMemlock, &restore, nil); err != nil {
			t.Errorf("cannot restore memlock limit: %s", err)
		}
	}()

	buffers.RLock()
	before := len(buffers.list)
	buffers.RUnlock()

	if _, err := NewBuffer(32); !IsResourceError(err) {
		t.Error("expected resource error; got", err)
	}
	if _, err := NewCoffer(); !IsResourceError(err) {
		t.Error("expected resource error; got", err)
	}
	if _, _, err := keyAndVersion(); err != nil && !IsResourceError(err) {
		t.Error("expected resource error or nil; got", err)
	}

	buffers.RLock()
	after := len(buffers.list)
	buffers.RUnlock()
	if before != after {
		t.Error("failed allocations leaked registrations")
	}

	// The session key survived: the live session still works once the
	// limit is back.
}

// TestResourceRecovery verifies the session works again after the limit is
// restored. It must run after TestResourceExhaustion (file order).
func TestResourceRecovery(t *testing.T) {
	b, err := NewBuffer(32)
	if err != nil {
		t.Fatal("session did not recover:", err)
	}
	b.Destroy()
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal("session did not recover:", err)
	}
	buf, err := Open(e)
	if err != nil {
		t.Fatal("session did not recover:", err)
	}
	buf.Destroy()
}
