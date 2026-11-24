/*
Package memarmor implements a secure software enclave for the storage of sensitive information in memory.

	package main

	import (
		"fmt"
		"os"

		"github.com/marcgauthier/memarmor"
	)

	func main() {
		// Safely terminate in case of an interrupt signal
		memarmor.CatchInterrupt()

		// Purge the session when we return
		defer memarmor.Purge()

		// Generate a key sealed inside an encrypted container
		key := memarmor.NewEnclaveRandom(32)

		// Passing the key off to another function
		key = invert(key)

		// Decrypt the result returned from invert
		keyBuf, err := key.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer keyBuf.Destroy()

		// Um output it
		fmt.Println(keyBuf.Bytes())
	}

	func invert(key *memarmor.Enclave) *memarmor.Enclave {
		// Decrypt the key into a local copy
		b, err := key.Open()
		if err != nil {
			memarmor.SafePanic(err)
		}
		defer b.Destroy() // Destroy the copy when we return

		// Open returns the data in an immutable buffer, so make it mutable
		b.Melt()

		// Set every element to its complement
		for i := range b.Bytes() {
			b.Bytes()[i] = ^b.Bytes()[i]
		}

		// Return the new data in encrypted form
		return b.Seal() // <- sealing also destroys b
	}

There are two main container objects exposed in this API. Enclave objects encrypt data and store the ciphertext whereas LockedBuffers are more like guarded memory allocations. There is a limit on the maximum number of LockedBuffer objects that can exist at any one time, imposed by the system's mlock limits. There is no limit on Enclaves.

The general workflow is to store sensitive information in Enclaves when it is not immediately needed and decrypt it when and where it is. After use, the LockedBuffer should be destroyed.

If you need access to the data inside a LockedBuffer in a type not covered by any methods provided by this API, you can type-cast the allocation's memory to whatever type you want.

	key := memarmor.NewBuffer(32)
	keyArrayPtr := (*[32]byte)(unsafe.Pointer(&key.Bytes()[0])) // do not dereference

This is of course an unsafe operation and so care must be taken to ensure that the cast is valid and does not result in memory unsafety. Further examples of code and interesting use-cases can be found in the examples subpackage.

Several functions exist to make the mass purging of data very easy. It is recommended to make use of them when appropriate.

	// Start an interrupt handler that will clean up memory before exiting
	memarmor.CatchInterrupt()

	// Purge the session when returning from the main function of your program
	defer memarmor.Purge()

	// Use the safe variants of exit functions provided in the stdlib
	memarmor.SafeExit(1)
	memarmor.SafePanic(err)

	// Destroy LockedBuffers as soon as possible after using them
	b, err := enclave.Open()
	if err != nil {
		memarmor.SafePanic(err)
	}
	defer b.Destroy()

Core dumps are disabled by default. If you absolutely require them, you can enable them by using unix.Setrlimit to set RLIMIT_CORE to an appropriate value.

The sealing cipher can be switched between XSalsa20-Poly1305 and
AES-256-GCM-SIV with SetCipher, either globally or per enclave. When a TPM
2.0 is available the session key is sealed to it automatically; use
LockSessionKey and UnlockSessionKey to evict the key from RAM between uses,
and SetTPMSealPolicy to bind seals to a measured boot state. Streams should
be closed with Close once writing finishes so readers can detect truncation,
and destroyed with Destroy when abandoned early.
*/
package memarmor
