package core

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/marcgauthier/memarmor/internal/memcall"
)

var sessionMu sync.RWMutex

// ErrSessionBusy indicates that the session is changing and the operation can be retried.
var ErrSessionBusy = errors.New("<memarmor::core> session transition in progress")

// finishSession releases an operation before handling an internal panic, since
// purging needs exclusive access to the session.
func finishSession() {
	sessionMu.RUnlock()
	if v := recover(); v != nil {
		Panic(v)
	}
}

func finishSessionTransition() {
	sessionMu.Unlock()
	if v := recover(); v != nil {
		Panic(v)
	}
}

/*
Purge wipes all sensitive data and keys before reinitialising the session with a fresh encryption key and secure values. Subsequent library operations will use these fresh values and the old data is assumed to be practically unrecoverable.

The creation of new Enclave objects should wait for this function to return since subsequent Enclave objects will use the newly created key.

This function should be called before the program terminates, or else the provided Exit or Panic functions should be used to terminate.
*/
func Purge() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if err := purgeSession(); err != nil {
		panic(err)
	}
}

// purgeSession runs with exclusive session access.
func purgeSession() error {
	var opErr error

	keyMtx.Lock()

	// A purge retires the session key entirely: drop any TPM-sealed
	// copy so it can never unlock the old key again.
	Wipe(sealedKey)
	sealedKey = nil
	keyLocked = false
	tpmState = TPMUnused

	// Destroy the session key explicitly instead of relying on its buffers
	// happening to be in the global list.
	if !key.Destroyed() {
		if err := key.Destroy(); err != nil {
			opErr = err
		}
	}
	keyMtx.Unlock()

	// Get a snapshot of existing Buffers.
	snapshot := buffers.flush()

	// Destroy them, performing the usual sanity checks.
	for _, b := range snapshot {
		if err := b.destroy(); err != nil {
			if opErr == nil {
				opErr = err
			} else {
				opErr = fmt.Errorf("%s; %s", opErr.Error(), err.Error())
			}
			// Buffer destruction failed; wipe what we can instead.
			// Each buffer is unlocked before moving on.
			b.Lock()
			if !b.mutable {
				if err := memcall.Protect(b.inner, memcall.ReadWrite()); err != nil {
					// couldn't change it to mutable; we can't wipe it! (could this happen?)
					// not sure what we can do at this point, just warn and move on
					fmt.Fprintf(os.Stderr, "!WARNING: failed to wipe immutable data at address %p", &b.data)
					b.Unlock()
					continue
				}
			}
			Wipe(b.data)
			b.Unlock()
		}
	}

	return opErr
}

/*
Exit terminates the process with a specified exit code but securely wipes and cleans up sensitive data before doing so.
*/
func Exit(c int) {
	sessionMu.Lock()
	if err := purgeSession(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(c)
}

/*
Panic is identical to the builtin panic except it purges the session before calling panic.
*/
func Panic(v any) {
	Purge() // creates a new key so it is safe to recover from this panic
	panic(v)
}
