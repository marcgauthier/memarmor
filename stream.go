package memarmor

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/marcgauthier/memarmor/core"
)

var (
	// StreamChunkSize is the maximum amount of data that is locked into memory at a time.
	// If you get error allocating memory, increase your system's mlock limits.
	// Use 'ulimit -l' to see mlock limit on unix systems.
	StreamChunkSize = c
	c               = os.Getpagesize() * 4
)

// ErrStreamClosed is returned when writing to a closed Stream.
var ErrStreamClosed = errors.New("<memarmor::ErrStreamClosed> write to closed stream")

// streamEndMarker is the payload of the terminator chunk appended by Close.
var streamEndMarker = []byte("MEMGUARD-STREAM\x00")

type queue struct {
	*list.List
}

// add data to back of queue
func (q *queue) join(e *Enclave) {
	q.PushBack(e)
}

// pop data off front of queue
// returns nil if queue is empty
func (q *queue) pop() *Enclave {
	e := q.Front() // get element at front of queue
	if e == nil {
		return nil // no data
	}
	q.Remove(e)               // success => remove value
	return e.Value.(*Enclave) // unwrap and return (potential panic)
}

/*
Stream is an in-memory encrypted container implementing the reader and writer interfaces.

It is most useful when you need to store lots of data in memory and are able to work on it in chunks.

Every chunk is bound to its stream and position, so reordered, transplanted
or duplicated chunks fail to open. Call Close once writing is finished: it
commits the total chunk count, which lets readers also detect truncation of
the tail. Destroy a Stream you abandon early to wipe its buffered data.
*/
type Stream struct {
	sync.Mutex
	*queue

	id       [16]byte // random stream identity bound into every chunk
	writeSeq uint64   // chunks sealed so far
	consumed uint64   // chunks fully consumed so far

	closed        bool
	expectedTotal uint64 // chunk count committed by Close (marker included)
	queuedBytes   int    // user plaintext bytes currently queued (marker excluded)

	pending    *LockedBuffer // partially consumed chunk
	pendingOff int
}

// NewStream initialises a new empty Stream object.
func NewStream() *Stream {
	s := &Stream{queue: &queue{List: list.New()}}
	ScrambleBytes(s.id[:])
	return s
}

// chunkAD reconstructs the data-chunk associated data for a sequence number.
func (s *Stream) chunkAD(seq uint64) []byte {
	ad := make([]byte, 24)
	copy(ad, s.id[:])
	binary.BigEndian.PutUint64(ad[16:], seq)
	return ad
}

// markerAD reconstructs the end-marker associated data. It lives in a
// different namespace from data chunks so a shifted marker never parses
// as data.
func (s *Stream) markerAD(seq uint64) []byte {
	ad := make([]byte, 25)
	copy(ad, s.id[:])
	binary.BigEndian.PutUint64(ad[16:], seq)
	ad[24] = 0xff
	return ad
}

// expectedAD returns the associated data the next chunk must carry: the
// marker namespace at the committed final position, data elsewhere.
func (s *Stream) expectedAD(seq uint64) []byte {
	if s.closed && s.expectedTotal > 0 && seq == s.expectedTotal-1 {
		return s.markerAD(seq)
	}
	return s.chunkAD(seq)
}

/*
Write encrypts and writes some given data to a Stream object.

The data is broken down into chunks and added to the stream in order. The last thing to be written to the stream is the last thing that will be read back.

The input is wiped chunk by chunk as it is sealed. Writing to a closed
Stream reports ErrStreamClosed. A locked session or exhausted memory is
reported with the number of bytes sealed so far.
*/
func (s *Stream) Write(data []byte) (int, error) {
	s.Lock()
	defer s.Unlock()

	if s.closed {
		return 0, ErrStreamClosed
	}

	for i := 0; i < len(data); i += c {
		end := i + c
		if end > len(data) {
			end = len(data)
		}
		ce, err := core.NewEnclaveAD(data[i:end], s.chunkAD(s.writeSeq))
		if err != nil {
			// The unwritten tail is untouched.
			return i, err
		}
		s.writeSeq++
		s.queuedBytes += end - i
		s.join(&Enclave{ce})
	}
	return len(data), nil
}

/*
Close commits a Stream: no more writes are accepted and a sealed end marker
lets readers detect a truncated tail. Close is idempotent.
*/
func (s *Stream) Close() error {
	s.Lock()
	defer s.Unlock()

	if s.closed {
		return nil
	}
	marker := append([]byte{}, streamEndMarker...)
	ce, err := core.NewEnclaveAD(marker, s.markerAD(s.writeSeq))
	if err != nil {
		return err
	}
	e := &Enclave{ce}
	s.writeSeq++
	s.expectedTotal = s.writeSeq
	s.closed = true
	s.join(e)
	return nil
}

// fill pops the next chunk into pending. It reports io.EOF at a clean end
// and io.ErrUnexpectedEOF when a closed stream ends early.
func (s *Stream) fill() error {
	e := s.pop()
	if e == nil {
		if s.closed && s.consumed != s.expectedTotal {
			return io.ErrUnexpectedEOF
		}
		return io.EOF
	}
	b, err := e.OpenWithAD(s.expectedAD(s.consumed))
	if err != nil {
		return err
	}
	s.consumed++
	// The final chunk of a closed stream is the end marker, not data.
	if s.closed && s.consumed == s.expectedTotal {
		defer b.Destroy()
		if !bytes.Equal(b.Bytes(), streamEndMarker) {
			return core.ErrDecryptionFailed
		}
		return io.EOF
	}
	s.pending = b
	s.pendingOff = 0
	s.queuedBytes -= b.Size()
	return nil
}

/*
Read decrypts and places some data from a Stream object into a provided buffer.

Partially consumed chunks are buffered inside the Stream until fully read. At
a clean end Read reports io.EOF; if a closed stream ends early it reports
io.ErrUnexpectedEOF instead.

To be performant, read in multiples of the chunk size.
*/
func (s *Stream) Read(buf []byte) (int, error) {
	s.Lock()
	defer s.Unlock()

	if s.pending == nil {
		if err := s.fill(); err != nil {
			return 0, err
		}
	}
	if len(buf) == 0 {
		return 0, nil
	}
	n := copy(buf, s.pending.Bytes()[s.pendingOff:])
	s.pendingOff += n
	if s.pendingOff == s.pending.Size() {
		s.pending.Destroy()
		s.pending = nil
		s.pendingOff = 0
	}
	return n, nil
}

// Size returns the number of bytes of user data currently buffered within a Stream object.
func (s *Stream) Size() int {
	s.Lock()
	defer s.Unlock()

	n := s.queuedBytes
	if s.pending != nil {
		n += s.pending.Size() - s.pendingOff
	}
	return n
}

// Next grabs the next chunk of data from the Stream and returns it decrypted inside a LockedBuffer. Any error from the stream is forwarded.
func (s *Stream) Next() (*LockedBuffer, error) {
	s.Lock()
	defer s.Unlock()

	if s.pending != nil {
		// Hand over the remainder of the current chunk.
		rb, err := core.NewBuffer(s.pending.Size() - s.pendingOff)
		if err != nil {
			s.pending.Destroy()
			s.pending = nil
			s.pendingOff = 0
			return newNullBuffer(), err
		}
		rest := newBuffer(rb)
		rest.Copy(s.pending.Bytes()[s.pendingOff:])
		rest.Freeze()
		s.pending.Destroy()
		s.pending = nil
		s.pendingOff = 0
		return rest, nil
	}
	if err := s.fill(); err != nil {
		return newNullBuffer(), err
	}
	b := s.pending
	s.pending = nil
	s.pendingOff = 0
	return b, nil
}

// Flush reads all of the data from a Stream and returns it inside a LockedBuffer. If an error is encountered before all the data could be read, it is returned along with any data read up until that point.
func (s *Stream) Flush() (*LockedBuffer, error) {
	return NewBufferFromEntireReader(s)
}

/*
Destroy wipes any buffered plaintext and all queued ciphertext. A destroyed
Stream reads back as empty and rejects further writes.
*/
func (s *Stream) Destroy() {
	s.Lock()
	defer s.Unlock()

	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
		s.pendingOff = 0
	}
	for {
		e := s.pop()
		if e == nil {
			break
		}
		e.Destroy()
	}
	s.queuedBytes = 0
	s.closed = true
	s.expectedTotal = s.consumed
}
