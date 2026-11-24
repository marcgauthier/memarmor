package memarmor

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"testing"

	"github.com/marcgauthier/memarmor/core"
)

func write(t *testing.T, s *Stream, b []byte) {
	n, err := s.WriteAndWipe(b)
	if err != nil {
		t.Error("write should always succeed", err)
	}
	if n != len(b) {
		t.Error("not all data was written")
	}
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Error("buffer not wiped")
	}
}

func TestStreamWritePreservesInput(t *testing.T) {
	s := NewStream()
	defer s.Destroy()
	want := bytes.Repeat([]byte{0x33}, StreamChunkSize+1)
	src := bytes.Clone(want)
	var other bytes.Buffer
	n, err := io.MultiWriter(s, &other).Write(src)
	if err != nil || n != len(src) || !bytes.Equal(src, want) || !bytes.Equal(other.Bytes(), want) {
		t.Fatalf("Write failed to preserve the input: %d, %v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Flush()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if !got.EqualTo(want) {
		t.Fatal("stream data mismatch")
	}
}

func read(t *testing.T, s *Stream, ref []byte, expectedErr error) {
	b := make([]byte, len(ref))
	n, err := s.Read(b)
	if err != expectedErr {
		t.Error("Expected", expectedErr, "got;", err)
	}
	if n != len(b) {
		t.Error("not enough data read")
	}
	if !bytes.Equal(ref, b) {
		t.Error("data mismatch")
	}
}

func TestStreamNextFlush(t *testing.T) {
	s := NewStream()

	size := 2*StreamChunkSize + 1024
	b := make([]byte, size)
	ScrambleBytes(b)
	ref := make([]byte, len(b))
	copy(ref, b)
	write(t, s, b)

	c, err := s.Next()
	if err != nil {
		t.Error(err)
	}
	if c.Size() != StreamChunkSize {
		t.Error(c.Size())
	}
	if !c.EqualTo(ref[:StreamChunkSize]) {
		t.Error("incorrect data")
	}
	c.Destroy()

	c, err = s.Flush()
	if err != nil {
		t.Error(err)
	}
	if c.Size() != size-StreamChunkSize {
		t.Error("unexpected length:", c.Size())
	}
	if !c.EqualTo(ref[StreamChunkSize:]) {
		t.Error("incorrect data")
	}
	c.Destroy()
}

func TestStreamReadWrite(t *testing.T) {
	// Create new stream object.
	s := NewStream()

	// Initialise some data to store.
	b := make([]byte, 1024)
	ScrambleBytes(b)
	ref := make([]byte, len(b))
	copy(ref, b)

	// Write the data to the stream.
	write(t, s, b)

	// Read the data back.
	read(t, s, ref, nil)

	// Check for end of data error
	read(t, s, nil, io.EOF)

	// Write more than the pagesize to the stream
	b = make([]byte, os.Getpagesize()*4+16)
	ScrambleBytes(b)
	copy(b[os.Getpagesize()*4:], []byte("yellow submarine"))
	ref = make([]byte, len(b))
	copy(ref, b)
	write(t, s, b)

	// Read back four pages
	for i := range 4 {
		read(t, s, ref[i*os.Getpagesize():(i+1)*os.Getpagesize()], nil)
	}

	// Read back the remaining data
	read(t, s, []byte("yellow submarine"), nil)

	// Should be no data left
	read(t, s, nil, io.EOF)

	// Test reading less data than is in the chunk
	data := make([]byte, 16)
	ScrambleBytes(data)
	ref = make([]byte, len(data))
	copy(ref, data)
	write(t, s, data)
	write(t, s, data) // have two enclaves in the stream, 32 bytes total
	read(t, s, ref[:4], nil)
	read(t, s, ref[4:8], nil)
	read(t, s, ref[8:], nil)
	read(t, s, make([]byte, 16), nil)
	read(t, s, nil, io.EOF)

	// Test reading after purging the session
	ScrambleBytes(data)
	write(t, s, data)
	Purge()
	read(t, s, nil, core.ErrDecryptionFailed)
}

func TestStreamingSanity(t *testing.T) {
	s := NewStream()

	// write 2 pages + 1024 bytes to the stream
	size := 2*os.Getpagesize() + 1024
	b := make([]byte, size)
	ScrambleBytes(b)
	ref := make([]byte, len(b))
	copy(ref, b)
	write(t, s, b)

	// read it back exactly
	c, err := NewBufferFromReader(s, size)
	if err != nil {
		t.Error(err)
	}
	if c.Size() != size {
		t.Error("not enough data read back")
	}
	if !c.EqualTo(ref) {
		t.Error("data mismatch")
	}
	c.Destroy()

	// should be no data left
	read(t, s, nil, io.EOF)

	// write the data back to the stream
	copy(b, ref)
	write(t, s, b)

	// read it all back
	c, err = NewBufferFromEntireReader(s)
	if err != nil {
		t.Error(err)
	}
	if c.Size() != size {
		t.Error("not enough data read back")
	}
	if !c.EqualTo(ref) {
		t.Error("data mismatch")
	}
	c.Destroy()

	// should be no data left
	read(t, s, nil, io.EOF)

	// write a page + 1024 bytes
	size = os.Getpagesize() + 1024
	b = make([]byte, size)
	b[size-1] = 'x'
	write(t, s, b)

	// read it back until the delimiter
	c, err = NewBufferFromReaderUntil(s, 'x')
	if err != nil {
		t.Error(err)
	}
	if c.Size() != size-1 {
		t.Error("not enough data read back:", c.Size(), "want", size-1)
	}
	if !c.EqualTo(make([]byte, size-1)) {
		t.Error("data mismatch")
	}
	c.Destroy()

	// should be no data left
	read(t, s, nil, io.EOF)
}

func TestStreamSize(t *testing.T) {
	s := NewStream()

	if s.Size() != 0 {
		t.Error("size is", s.Size())
	}

	size := 1024 * 32
	b := make([]byte, size)
	write(t, s, b)

	if s.Size() != size {
		t.Error("size should be", size, "instead is", s.Size())
	}
}

func BenchmarkStreamWrite(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(StreamChunkSize))

	s := NewStream()
	buf := make([]byte, StreamChunkSize)
	for i := 0; i < b.N; i++ {
		s.Write(buf)
	}
	runtime.KeepAlive(s)
}

func BenchmarkStreamRead(b *testing.B) {
	s := NewStream()
	buf := make([]byte, StreamChunkSize)
	for i := 0; i < b.N; i++ {
		s.Write(buf)
	}

	b.ReportAllocs()
	b.SetBytes(int64(StreamChunkSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.Read(buf)
	}

	runtime.KeepAlive(s)
}

func TestStreamCloseFlush(t *testing.T) {
	s := NewStream()
	data := make([]byte, 2*StreamChunkSize+100)
	ScrambleBytes(data)
	ref := append([]byte{}, data...)
	write(t, s, data)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Size() != len(ref) {
		t.Error("marker leaked into size:", s.Size())
	}
	c, err := s.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if !c.EqualTo(ref) {
		t.Error("data mismatch after close")
	}
	c.Destroy()
	read(t, s, nil, io.EOF)
	if err := s.Close(); err != nil {
		t.Error("close is not idempotent:", err)
	}
	if _, err := s.Write([]byte("x")); err != ErrStreamClosed {
		t.Error("expected closed error; got", err)
	}
}

func TestStreamTruncation(t *testing.T) {
	newClosed := func(t *testing.T) *Stream {
		s := NewStream()
		for _, msg := range [][]byte{[]byte("chunk-A-payload"), []byte("chunk-B-payload")} {
			m := append([]byte{}, msg...)
			write(t, s, m)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Dropping a data chunk shifts the marker into a data slot, where its
	// marker-namespace seal fails authentication.
	s := newClosed(t)
	s.queue.Remove(s.queue.Back().Prev()) // drop chunk B, keep marker
	c, err := s.Flush()
	if err != core.ErrDecryptionFailed {
		t.Error("expected auth error; got", err)
	}
	if !c.EqualTo([]byte("chunk-A-payload")) {
		t.Error("partial data mismatch")
	}
	c.Destroy()

	// Dropping only the marker is detected too.
	s = newClosed(t)
	s.queue.Remove(s.queue.Back())
	if _, err := s.Flush(); err != io.ErrUnexpectedEOF {
		t.Error("expected truncation error; got", err)
	}

	// Without Close there is nothing to check against: plain EOF.
	s = NewStream()
	write(t, s, append([]byte{}, []byte("chunk-A-payload")...))
	c, err = s.Flush()
	if err != nil {
		t.Error(err)
	}
	c.Destroy()
	read(t, s, nil, io.EOF)
}

func TestStreamReorder(t *testing.T) {
	s := NewStream()
	write(t, s, append([]byte{}, []byte("chunk-A-payload")...))
	write(t, s, append([]byte{}, []byte("chunk-B-payload")...))
	// Swap the two queued chunks.
	s.queue.MoveAfter(s.queue.Front(), s.queue.Back())
	read(t, s, nil, core.ErrDecryptionFailed)
}

func TestStreamTransplant(t *testing.T) {
	s1, s2 := NewStream(), NewStream()
	write(t, s1, append([]byte{}, []byte("chunk-A-payload")...))
	write(t, s2, append([]byte{}, []byte("chunk-B-payload")...))
	// Move s2's chunk behind s1's data.
	s1.queue.PushBack(s2.queue.Remove(s2.queue.Front()))
	read(t, s1, []byte("chunk-A-payload"), nil)
	read(t, s1, nil, core.ErrDecryptionFailed)
}

func TestStreamDestroy(t *testing.T) {
	s := NewStream()
	m := make([]byte, 100)
	ScrambleBytes(m)
	write(t, s, m)
	if _, err := s.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	s.Destroy()
	if s.Size() != 0 {
		t.Error("expected empty stream")
	}
	read(t, s, nil, io.EOF)
	if _, err := s.Write([]byte("x")); err != ErrStreamClosed {
		t.Error("expected closed error; got", err)
	}
}

func TestStreamNextAfterPartial(t *testing.T) {
	s := NewStream()
	m := make([]byte, 100)
	ScrambleBytes(m)
	ref := append([]byte{}, m...)
	write(t, s, m)
	if _, err := s.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	nx, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !nx.EqualTo(ref[10:]) {
		t.Error("remainder mismatch")
	}
	if nx.IsMutable() {
		t.Error("expected immutable chunk")
	}
	nx.Destroy()
	read(t, s, nil, io.EOF)
}
