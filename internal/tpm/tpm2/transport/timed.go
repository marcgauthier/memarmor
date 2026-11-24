package transport

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/marcgauthier/memarmor/internal/tpm/tpmutil"
)

// Restrict the number of platform handles and workers, including when a
// native driver has stopped returning from a syscall.
var platformTPMSlot = make(chan struct{}, 1)

type timedTPM struct {
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
	requests chan timedRequest
	done     chan struct{}
	closeErr error
}

type timedRequest struct {
	packet []byte
	reply  chan timedResponse
}

type timedResponse struct {
	packet []byte
	err    error
}

// OpenWithTimeout bounds platform I/O from opening the TPM through the
// lifetime of the returned connection. The worker owns the device and copies
// of wire packets. A timed-out caller can release its state while a blocked
// native syscall completes.
func OpenWithTimeout(open func() (io.ReadWriteCloser, error), timeout time.Duration) (TPMCloser, error) {
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	select {
	case platformTPMSlot <- struct{}{}:
	case <-ctx.Done():
		cancel()
		return nil, tpmutil.ErrTimeout
	}
	t := &timedTPM{
		ctx: ctx, cancel: cancel, deadline: deadline,
		requests: make(chan timedRequest), done: make(chan struct{}),
	}
	opened := make(chan error, 1)
	go t.run(open, opened)
	select {
	case err := <-opened:
		if ctx.Err() == nil && err == nil {
			return t, nil
		}
		if ctx.Err() == nil {
			cancel()
			return nil, err
		}
	case <-ctx.Done():
	}
	cancel()
	return nil, tpmutil.ErrTimeout
}

func (t *timedTPM) run(open func() (io.ReadWriteCloser, error), opened chan<- error) {
	defer close(t.done)
	defer func() { <-platformTPMSlot }()
	if t.ctx.Err() != nil {
		return
	}
	rw, err := open()
	if rw != nil {
		defer func() { t.closeErr = rw.Close() }()
	}
	opened <- err
	if err != nil {
		return
	}

	for {
		select {
		case <-t.ctx.Done():
			return
		case req := <-t.requests:
			if t.ctx.Err() != nil {
				return
			}
			packet, err := tpmutil.RunCommandRawUntil(rw, req.packet, t.deadline)
			req.reply <- timedResponse{packet, err}
		}
	}
}

func (t *timedTPM) Send(packet []byte) ([]byte, error) {
	req := timedRequest{bytes.Clone(packet), make(chan timedResponse, 1)}
	select {
	case <-t.ctx.Done():
		return nil, t.interrupted()
	case t.requests <- req:
	}
	select {
	case <-t.ctx.Done():
		return nil, t.interrupted()
	case result := <-req.reply:
		if t.ctx.Err() != nil {
			return nil, t.interrupted()
		}
		return result.packet, result.err
	}
}

func (t *timedTPM) interrupted() error {
	if !time.Now().Before(t.deadline) {
		return tpmutil.ErrTimeout
	}
	return io.ErrClosedPipe
}

func (t *timedTPM) Close() error {
	t.cancel()
	select {
	case <-t.done:
		return t.closeErr
	default:
	}
	if !time.Now().Before(t.deadline) {
		return tpmutil.ErrTimeout
	}
	timer := time.NewTimer(time.Until(t.deadline))
	defer timer.Stop()
	select {
	case <-t.done:
		return t.closeErr
	case <-timer.C:
		return tpmutil.ErrTimeout
	}
}
