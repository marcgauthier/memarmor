package memarmor

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/marcgauthier/memarmor/core"
)

var (
	// Ensure we only start a single signal handling instance
	create sync.Once

	handlerMu sync.RWMutex
	handler   func(os.Signal)

	// Channel that caught signals are sent to by the runtime
	listener = make(chan os.Signal, 32)
)

/*
CatchSignal assigns a given function to be run in the event of a signal being received by the process. If no signals are provided all signals will be caught.

 1. Signal is caught by the process
 2. Interrupt handler is executed
 3. Secure session state is wiped
 4. Process terminates with exit code 1

This function can be called multiple times with the effect that only the last call will have any effect.
*/
func CatchSignal(f func(os.Signal), signals ...os.Signal) {
	handlerMu.Lock()
	handler = f
	handlerMu.Unlock()

	create.Do(func() {
		go func() {
			sig := <-listener
			defer core.Exit(1)
			handlerMu.RLock()
			f := handler
			handlerMu.RUnlock()
			if f != nil {
				f(sig)
			}
		}()
	})

	// Notify the channel if we receive a signal. Channels registered by
	// anyone else keep working; nothing is reset.
	signal.Notify(listener, signals...)
}

/*
CatchInterrupt is a wrapper around CatchSignal that makes it easy to safely handle receiving interrupt signals. If an interrupt is received, the process will wipe sensitive data in memory before terminating.

A subsequent call to CatchSignal will override this call.
*/
func CatchInterrupt() {
	CatchSignal(func(_ os.Signal) {}, os.Interrupt)
}

/*
CatchTermination is a wrapper around CatchSignal that makes it easy to safely handle receiving interrupt and termination signals. If one is received, the process will wipe sensitive data in memory before terminating.

A subsequent call to CatchSignal will override this call.
*/
func CatchTermination() {
	CatchSignal(func(_ os.Signal) {}, os.Interrupt, syscall.SIGTERM)
}
