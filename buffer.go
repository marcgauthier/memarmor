package memarmor

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"unsafe"

	"github.com/marcgauthier/memarmor/core"
)

// nativeOrder decodes multi-byte integers the way the platform's native
// casts would, so typed copies keep their values on any endianness.
var nativeOrder = func() binary.ByteOrder {
	var i uint16 = 1
	if *(*byte)(unsafe.Pointer(&i)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

/*
LockedBuffer is a structure that holds raw sensitive data.

The number of LockedBuffers that you are able to create is limited by how much memory your system's kernel allows each process to mlock/VirtualLock. Therefore you should call Destroy on LockedBuffers that you no longer need or defer a Destroy call after creating a new LockedBuffer.
*/
type LockedBuffer struct {
	*core.Buffer
}

// Constructs a LockedBuffer object from a core.Buffer while also setting up the finalizer for it.
func newBuffer(buf *core.Buffer) *LockedBuffer {
	return &LockedBuffer{buf}
}

// Constructs a quasi-destroyed LockedBuffer with size zero.
func newNullBuffer() *LockedBuffer {
	return &LockedBuffer{new(core.Buffer)}
}

/*
NewBuffer creates a mutable data container of the specified size. It returns
a null buffer for a non-positive size or when guarded memory cannot be
allocated or locked.
*/
func NewBuffer(size int) *LockedBuffer {
	// Construct a Buffer of the specified size.
	buf, err := core.NewBuffer(size)
	if err != nil {
		return newNullBuffer()
	}

	// Construct and return the wrapped container object.
	return newBuffer(buf)
}

/*
NewBufferFromBytes constructs an immutable buffer from a byte slice. The source buffer is wiped after the value has been copied over to the created container.
*/
func NewBufferFromBytes(src []byte) *LockedBuffer {
	// Construct a buffer of the correct size.
	b := NewBuffer(len(src))
	if b.Size() == 0 {
		return b
	}

	// Move the data over.
	b.Move(src)

	// Make the buffer immutable.
	b.Freeze()

	// Return the created Buffer object.
	return b
}

/*
NewBufferFromReader reads some number of bytes from an io.Reader into an immutable LockedBuffer.

An error is returned precisely when the number of bytes read is less than the requested amount. Any data read is returned in either case.
*/
func NewBufferFromReader(r io.Reader, size int) (*LockedBuffer, error) {
	// Construct a buffer of the provided size.
	b := NewBuffer(size)
	if b.Size() == 0 {
		return b, nil
	}

	// Attempt to fill it with data from the Reader.
	if n, err := io.ReadFull(r, b.Bytes()); err != nil {
		if n == 0 {
			// nothing was read
			b.Destroy()
			return newNullBuffer(), err
		}

		// partial read
		d := NewBuffer(n)
		d.Copy(b.Bytes()[:n])
		d.Freeze()
		b.Destroy()
		return d, err
	}

	// success
	b.Freeze()
	return b, nil
}

/*
NewBufferFromReaderUntil constructs an immutable buffer containing data sourced from an io.Reader object.

If an error is encountered before the delimiter value, the error will be returned along with the data read up until that point.
*/
func NewBufferFromReaderUntil(r io.Reader, delim byte) (*LockedBuffer, error) {
	// Construct a buffer with a data page that fills an entire memory page.
	b := NewBuffer(os.Getpagesize())

	// Loop over the buffer a byte at a time.
	for i := 0; ; i++ {
		// If we have filled this buffer...
		if i == b.Size() {
			// Construct a new buffer that is a page size larger.
			c := NewBuffer(b.Size() + os.Getpagesize())

			// Copy the data over.
			c.Copy(b.Bytes())

			// Destroy the old one and reassign its variable.
			b.Destroy()
			b = c
		}

		// Attempt to read a single byte.
		n, err := r.Read(b.Bytes()[i : i+1])
		if n != 1 { // if we did not read a byte
			if err == nil { // and there was no error
				i-- // try again
				continue
			}
			// if instead there was an error, we're done early
			if i == 0 { // no data read
				b.Destroy()
				return newNullBuffer(), err
			}
			d := NewBuffer(i)
			d.Copy(b.Bytes()[:i])
			d.Freeze()
			b.Destroy()
			return d, err
		}
		// we managed to read a byte, check if it was the delimiter
		// note that errors are ignored in this case where we got data
		if b.Bytes()[i] == delim {
			if i == 0 {
				// if first byte was delimiter, there's no data to return
				b.Destroy()
				return newNullBuffer(), nil
			}
			d := NewBuffer(i)
			d.Copy(b.Bytes()[:i])
			d.Freeze()
			b.Destroy()
			return d, nil
		}
	}
}

/*
NewBufferFromEntireReader reads from an io.Reader into an immutable buffer. It will continue reading until EOF.

A nil error is returned precisely when we managed to read all the way until EOF. Any data read is returned in either case.
*/
func NewBufferFromEntireReader(r io.Reader) (*LockedBuffer, error) {
	// Create a buffer with a data region of one page size.
	b := NewBuffer(os.Getpagesize())

	for read := 0; ; {
		// Attempt to read some data from the reader.
		n, err := r.Read(b.Bytes()[read:])

		// Nothing read but no error, try again.
		if n == 0 && err == nil {
			continue
		}

		// 1) so either have data and no error
		// 2) or have error and no data
		// 3) or both have data and have error

		// Increment the read count by the number of bytes that we just read.
		read += n

		if err != nil {
			// Suppress EOF error
			if err == io.EOF {
				err = nil
			}
			// We're done, return the data.
			if read == 0 {
				// No data read.
				b.Destroy()
				return newNullBuffer(), err
			}
			d := NewBuffer(read)
			d.Copy(b.Bytes()[:read])
			d.Freeze()
			b.Destroy()
			return d, err
		}

		// If we've filled this buffer, grow it by another page size.
		if len(b.Bytes()[read:]) == 0 {
			d := NewBuffer(b.Size() + os.Getpagesize())
			d.Copy(b.Bytes())
			b.Destroy()
			b = d
		}
	}
}

/*
NewBufferRandom constructs an immutable buffer filled with cryptographically-secure random bytes.
*/
func NewBufferRandom(size int) *LockedBuffer {
	// Construct a buffer of the specified size.
	b := NewBuffer(size)
	if b.Size() == 0 {
		return b
	}

	// Fill the buffer with random bytes.
	b.Scramble()

	// Make the buffer immutable.
	b.Freeze()

	// Return the created Buffer object.
	return b
}

// Freeze makes a LockedBuffer's memory immutable. The call can be reversed with Melt.
func (b *LockedBuffer) Freeze() {
	b.Buffer.Freeze()
}

// Melt makes a LockedBuffer's memory mutable. The call can be reversed with Freeze.
func (b *LockedBuffer) Melt() {
	b.Buffer.Melt()
}

/*
Seal takes a LockedBuffer object and returns its contents encrypted inside a sealed Enclave object. The LockedBuffer is subsequently destroyed and its contents wiped.

If Seal is called on a destroyed buffer, a nil enclave is returned.
*/
func (b *LockedBuffer) Seal() *Enclave {
	return b.SealWithCipher(GetCipher())
}

/*
SealWithCipher takes a LockedBuffer object and returns its contents encrypted inside a sealed Enclave object using the given cipher. The LockedBuffer is subsequently destroyed and its contents wiped.

If SealWithCipher is called on a destroyed buffer, a nil enclave is returned.
A nil enclave is also returned when memory resources are exhausted.
*/
func (b *LockedBuffer) SealWithCipher(c Cipher) *Enclave {
	e, err := core.SealWithCipher(b.Buffer, c)
	if err != nil {
		if err == core.ErrBufferExpired || core.IsResourceError(err) {
			return nil
		}
		core.Panic(err)
	}
	return &Enclave{e}
}

/*
Copy copies src into a LockedBuffer. It panics if src does not fit. Move is preferred if the source is not also a LockedBuffer or if the source is no longer needed.
*/
func (b *LockedBuffer) Copy(src []byte) {
	b.CopyAt(0, src)
}

/*
CopyAt copies src into a LockedBuffer at an offset. It panics on an out-of-range offset or if src does not fit. Move is preferred if the source is not also a LockedBuffer or if the source is no longer needed.
*/
func (b *LockedBuffer) CopyAt(offset int, src []byte) {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	dst := b.Bytes()
	if offset < 0 || offset > len(dst) {
		panic("<memarmor> copy offset out of range")
	}
	if len(src) > len(dst)-offset {
		panic("<memarmor> copy overflows locked buffer")
	}
	core.Copy(dst[offset:], src)
}

/*
Move moves src into a LockedBuffer. It panics if src does not fit. The source is wiped after the bytes are copied.
*/
func (b *LockedBuffer) Move(src []byte) {
	b.MoveAt(0, src)
}

/*
MoveAt moves src into a LockedBuffer at an offset. It panics on an out-of-range offset or if src does not fit. The source is wiped after the bytes are copied.
*/
func (b *LockedBuffer) MoveAt(offset int, src []byte) {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	dst := b.Bytes()
	if offset < 0 || offset > len(dst) {
		panic("<memarmor> move offset out of range")
	}
	if len(src) > len(dst)-offset {
		panic("<memarmor> move overflows locked buffer")
	}
	core.Move(dst[offset:], src)
}

/*
Scramble attempts to overwrite the data with cryptographically-secure random bytes.
*/
func (b *LockedBuffer) Scramble() {
	if !b.IsAlive() {
		return
	}

	b.Buffer.Scramble()
}

/*
Wipe attempts to overwrite the data with zeros.
*/
func (b *LockedBuffer) Wipe() {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	core.Wipe(b.Bytes())
}

/*
Size gives you the length of a given LockedBuffer's data segment. A destroyed LockedBuffer will have a size of zero.
*/
func (b *LockedBuffer) Size() int {
	return len(b.Bytes())
}

/*
Destroy wipes and frees the underlying memory of a LockedBuffer. The LockedBuffer will not be accessible or usable after this calls is made.

Destroy must not race with concurrent use of the buffer: no other goroutine
may be inside Bytes, Reader, the typed views, WithBytes, or any mutating call
while Destroy runs.
*/
func (b *LockedBuffer) Destroy() {
	b.Buffer.Destroy()
}

/*
IsAlive returns a boolean value indicating if a LockedBuffer is alive, i.e. that it has not been destroyed.
*/
func (b *LockedBuffer) IsAlive() bool {
	return b.Buffer.Alive()
}

/*
IsMutable returns a boolean value indicating if a LockedBuffer is mutable.
*/
func (b *LockedBuffer) IsMutable() bool {
	return b.Buffer.Mutable()
}

/*
EqualTo performs a time-constant comparison on the contents of a LockedBuffer with a given buffer. A destroyed LockedBuffer will always return false.
*/
func (b *LockedBuffer) EqualTo(buf []byte) bool {
	b.RLock()
	defer b.RUnlock()

	return core.Equal(b.Bytes(), buf)
}

/*
	Functions for representing the memory region as various data types.
*/

/*
Bytes returns a byte slice referencing the protected region of memory. The
slice is only valid while the buffer is alive: it must not be used after
Destroy, and Destroy must not run concurrently with its use.
*/
func (b *LockedBuffer) Bytes() []byte {
	return b.Buffer.Data()
}

/*
WithBytes runs fn with the protected region while holding the buffer's read
lock, so the view is stable for the call. The slice must not be retained
after fn returns, and fn must not call back into operations that destroy or
re-lock this buffer.
*/
func (b *LockedBuffer) WithBytes(fn func([]byte)) {
	if !b.IsAlive() {
		return
	}
	b.RLock()
	defer b.RUnlock()
	fn(b.Bytes())
}

/*
Reader returns a Reader object referencing the protected region of memory. Same lifetime rules as Bytes.
*/
func (b *LockedBuffer) Reader() *bytes.Reader {
	return bytes.NewReader(b.Bytes())
}

/*
String returns a copy of the protected region as a string.
*/
func (b *LockedBuffer) String() string {
	if !b.IsAlive() {
		return ""
	}
	b.RLock()
	defer b.RUnlock()
	return string(b.Bytes())
}

/*
Uint16 returns a copy of the protected region with the data represented as a sequence of unsigned 16 bit integers. Its length will be half that of the byte slice, excluding any remaining part that doesn't form a complete uint16 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint16() []uint16 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 2
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]uint16, size)
	for i := range out {
		out[i] = nativeOrder.Uint16(b.Bytes()[i*2:])
	}
	return out
}

/*
Uint32 returns a copy of the protected region with the data represented as a sequence of unsigned 32 bit integers. Its length will be one quarter that of the byte slice, excluding any remaining part that doesn't form a complete uint32 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint32() []uint32 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 4
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]uint32, size)
	for i := range out {
		out[i] = nativeOrder.Uint32(b.Bytes()[i*4:])
	}
	return out
}

/*
Uint64 returns a copy of the protected region with the data represented as a sequence of unsigned 64 bit integers. Its length will be one eighth that of the byte slice, excluding any remaining part that doesn't form a complete uint64 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint64() []uint64 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 8
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]uint64, size)
	for i := range out {
		out[i] = nativeOrder.Uint64(b.Bytes()[i*8:])
	}
	return out
}

/*
Int8 returns a copy of the protected region with the data represented as a sequence of signed 8 bit integers. If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int8() []int8 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Copy out byte by byte.
	out := make([]int8, b.Size())
	for i := range out {
		out[i] = int8(b.Bytes()[i])
	}
	return out
}

/*
Int16 returns a copy of the protected region with the data represented as a sequence of signed 16 bit integers. Its length will be half that of the byte slice, excluding any remaining part that doesn't form a complete int16 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int16() []int16 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 2
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]int16, size)
	for i := range out {
		out[i] = int16(nativeOrder.Uint16(b.Bytes()[i*2:]))
	}
	return out
}

/*
Int32 returns a copy of the protected region with the data represented as a sequence of signed 32 bit integers. Its length will be one quarter that of the byte slice, excluding any remaining part that doesn't form a complete int32 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int32() []int32 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 4
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]int32, size)
	for i := range out {
		out[i] = int32(nativeOrder.Uint32(b.Bytes()[i*4:]))
	}
	return out
}

/*
Int64 returns a copy of the protected region with the data represented as a sequence of signed 64 bit integers. Its length will be one eighth that of the byte slice, excluding any remaining part that doesn't form a complete int64 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int64() []int64 {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Compute size of new slice representation.
	size := b.Size() / 8
	if size < 1 {
		return nil
	}

	// Decode a copy in native byte order.
	out := make([]int64, size)
	for i := range out {
		out[i] = int64(nativeOrder.Uint64(b.Bytes()[i*8:]))
	}
	return out
}

/*
ByteArray8 returns a copy of the first 8 bytes as an array.

The length of the buffer must be at least 8 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray8() *[8]byte {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Check if the length is large enough.
	if len(b.Bytes()) < 8 {
		return nil
	}

	// Copy into a fresh array; the pointer never aliases locked memory.
	var out [8]byte
	copy(out[:], b.Bytes()[:8])
	return &out
}

/*
ByteArray16 returns a copy of the first 16 bytes as an array.

The length of the buffer must be at least 16 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray16() *[16]byte {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Check if the length is large enough.
	if len(b.Bytes()) < 16 {
		return nil
	}

	// Copy into a fresh array; the pointer never aliases locked memory.
	var out [16]byte
	copy(out[:], b.Bytes()[:16])
	return &out
}

/*
ByteArray32 returns a copy of the first 32 bytes as an array.

The length of the buffer must be at least 32 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray32() *[32]byte {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Check if the length is large enough.
	if len(b.Bytes()) < 32 {
		return nil
	}

	// Copy into a fresh array; the pointer never aliases locked memory.
	var out [32]byte
	copy(out[:], b.Bytes()[:32])
	return &out
}

/*
ByteArray64 returns a copy of the first 64 bytes as an array.

The length of the buffer must be at least 64 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray64() *[64]byte {

	// Check if still alive.
	if !b.Buffer.Alive() {
		return nil
	}

	b.RLock()
	defer b.RUnlock()

	// Check if the length is large enough.
	if len(b.Bytes()) < 64 {
		return nil
	}

	// Copy into a fresh array; the pointer never aliases locked memory.
	var out [64]byte
	copy(out[:], b.Bytes()[:64])
	return &out
}
