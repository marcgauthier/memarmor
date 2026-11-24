package memarmor

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand"
	"os"
	"runtime"
	"testing"
)

func TestPtrSafetyWithGC(t *testing.T) {
	dataToLock := []byte(`abcdefgh`)
	b := NewBufferFromBytes(dataToLock)
	dataPtr := b.Bytes()

	finalizerCalledChan := make(chan bool)
	runtime.SetFinalizer(b, func(_ *LockedBuffer) {
		finalizerCalledChan <- true
	})
	// b is now unreachable

	runtime.GC()
	finalizerCalled := <-finalizerCalledChan
	if finalizerCalled == false {
		t.Error("this should never occur")
	}

	// Check that data hasn't been garbage collected
	if !bytes.Equal(dataPtr, []byte(`abcdefgh`)) {
		t.Error("data does not have the value we set")
	}
}

func TestNewBuffer(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("buffer should not be nil")
	}
	if len(b.Bytes()) != 32 || cap(b.Bytes()) != 32 {
		t.Error("buffer sizes incorrect")
	}
	if !bytes.Equal(b.Bytes(), make([]byte, 32)) {
		t.Error("buffer is not zeroed")
	}
	if !b.IsMutable() {
		t.Error("buffer should be mutable")
	}
	if !b.IsAlive() {
		t.Error("buffer should not be destroyed")
	}
	b.Destroy()
	b = NewBuffer(0)
	if b.Bytes() != nil {
		t.Error("data slice should be nil")
	}
	if b.Size() != 0 {
		t.Error("size should be zero", b.Size())
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestNewBufferFromBytes(t *testing.T) {
	data := []byte("yellow submarine")
	b := NewBufferFromBytes(data)
	if b == nil {
		t.Error("buffer should not be nil")
	}
	if len(b.Bytes()) != 16 || cap(b.Bytes()) != 16 {
		t.Error("buffer sizes invalid")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("data does not match\n", b.Bytes(), "\n", data)
	}
	if !bytes.Equal(data, make([]byte, 16)) {
		t.Error("source buffer not wiped")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	if !b.IsAlive() {
		t.Error("buffer should not be destroyed")
	}
	b.Destroy()
	b = NewBufferFromBytes([]byte{})
	if b.Bytes() != nil {
		t.Error("data slice should be nil")
	}
	if b.Size() != 0 {
		t.Error("size should be zero", b.Size())
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestNewBufferFromReader(t *testing.T) {
	b, err := NewBufferFromReader(rand.Reader, 4096)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 4096 {
		t.Error("buffer of incorrect size")
	}
	if bytes.Equal(b.Bytes(), make([]byte, 4096)) {
		t.Error("didn't read from reader")
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()

	r := bytes.NewReader([]byte("yellow submarine"))
	b, err = NewBufferFromReader(r, 16)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 16 {
		t.Error("buffer of incorrect size")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()

	r = bytes.NewReader([]byte("yellow submarine"))
	b, err = NewBufferFromReader(r, 17)
	if err == nil {
		t.Error("expected error got nil;", err)
	}
	if b.Size() != 16 {
		t.Error("incorrect size")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()

	r = bytes.NewReader([]byte(""))
	b, err = NewBufferFromReader(r, 32)
	if err == nil {
		t.Error("expected error got nil")
	}
	if b.IsAlive() {
		t.Error("expected destroyed buffer")
	}
	if b.IsMutable() {
		t.Error("expected immutable buffer")
	}
	if b.Size() != 0 {
		t.Error("expected nul sized buffer")
	}
	r = bytes.NewReader([]byte("yellow submarine"))
	b, err = NewBufferFromReader(r, 0)
	if err != nil {
		t.Error(err)
	}
	if b.Bytes() != nil {
		t.Error("data slice should be nil")
	}
	if b.Size() != 0 {
		t.Error("size should be zero", b.Size())
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

type s struct {
	count int
}

func (reader *s) Read(p []byte) (n int, err error) {
	if mrand.Intn(2) == 0 {
		return 0, nil
	}
	reader.count++
	if reader.count == 5000 {
		copy(p, []byte{1})
		return 1, nil
	}
	copy(p, []byte{0})
	return 1, nil
}

func TestNewBufferFromReaderUntil(t *testing.T) {
	data := make([]byte, 5000)
	data[4999] = 1
	r := bytes.NewReader(data)
	b, err := NewBufferFromReaderUntil(r, 1)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 4999 {
		t.Error("buffer has incorrect size")
	}
	for i := range b.Bytes() {
		if b.Bytes()[i] != 0 {
			t.Error("incorrect data")
		}
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()

	r = bytes.NewReader(data[:32])
	b, err = NewBufferFromReaderUntil(r, 1)
	if err == nil {
		t.Error("expected error got nil")
	}
	if b.Size() != 32 {
		t.Error("invalid size")
	}
	for i := range b.Bytes() {
		if b.Bytes()[i] != 0 {
			t.Error("incorrect data")
		}
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()

	r = bytes.NewReader([]byte{'x'})
	b, err = NewBufferFromReaderUntil(r, 'x')
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 0 {
		t.Error("expected no data")
	}
	if b.IsAlive() {
		t.Error("expected dead buffer")
	}

	r = bytes.NewReader([]byte(""))
	b, err = NewBufferFromReaderUntil(r, 1)
	if err == nil {
		t.Error("expected error got nil")
	}
	if b.IsAlive() {
		t.Error("expected destroyed buffer")
	}
	if b.IsMutable() {
		t.Error("expected immutable buffer")
	}
	if b.Size() != 0 {
		t.Error("expected nul sized buffer")
	}

	rr := new(s)
	b, err = NewBufferFromReaderUntil(rr, 1)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 4999 {
		t.Error("invalid size")
	}
	for i := range b.Bytes() {
		if b.Bytes()[i] != 0 {
			t.Error("invalid data")
		}
	}
	if b.IsMutable() {
		t.Error("expected buffer to be immutable")
	}
	b.Destroy()
}

type ss struct {
	count int
}

func (reader *ss) Read(p []byte) (n int, err error) {
	if mrand.Intn(2) == 0 {
		return 0, nil
	}
	reader.count++
	if reader.count == 5000 {
		return 0, io.EOF
	}
	copy(p, []byte{0})
	return 1, nil
}

type se struct {
	count int
}

func (reader *se) Read(p []byte) (n int, err error) {
	copy(p, []byte{0})
	reader.count++
	if reader.count == 5000 {
		return 1, errors.New("shut up bro")
	}
	return 1, nil
}

func TestNewBufferFromEntireReader(t *testing.T) {
	r := bytes.NewReader([]byte("yellow submarine"))
	b, err := NewBufferFromEntireReader(r)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 16 {
		t.Error("incorrect size", b.Size())
	}
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("incorrect data", b.String())
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()

	data := make([]byte, 16000)
	ScrambleBytes(data)
	r = bytes.NewReader(data)
	b, err = NewBufferFromEntireReader(r)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != len(data) {
		t.Error("incorrect size", b.Size())
	}
	if !b.EqualTo(data) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()

	r = bytes.NewReader([]byte{})
	b, err = NewBufferFromEntireReader(r)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 0 {
		t.Error("buffer should be nil size")
	}
	if b.IsAlive() {
		t.Error("buffer should appear destroyed")
	}

	rr := new(ss)
	b, err = NewBufferFromEntireReader(rr)
	if err != nil {
		t.Error(err)
	}
	if b.Size() != 4999 {
		t.Error("incorrect size", b.Size())
	}
	if !b.EqualTo(make([]byte, 4999)) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()

	re := new(se)
	b, err = NewBufferFromEntireReader(re)
	if err == nil {
		t.Error("expected error got nil")
	}
	if b.Size() != 5000 {
		t.Error(b.Size())
	}
	if !b.EqualTo(make([]byte, 5000)) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()

	// real world test
	f, err := os.Open("LICENSE")
	if err != nil {
		t.Error(err)
	}
	data, err = io.ReadAll(f)
	if err != nil {
		t.Error(err)
	}
	_, err = f.Seek(0, 0)
	if err != nil {
		t.Error(err)
	}
	b, err = NewBufferFromEntireReader(f)
	if err != nil {
		t.Error(err)
	}
	if !b.EqualTo(data) {
		t.Error("incorrect data")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()
	f.Close()
}

func TestNewBufferRandom(t *testing.T) {
	b := NewBufferRandom(32)
	if b == nil {
		t.Error("buffer is nil")
	}
	if len(b.Bytes()) != 32 || cap(b.Bytes()) != 32 {
		t.Error("buffer sizes incorrect")
	}
	if bytes.Equal(b.Bytes(), make([]byte, 32)) {
		t.Error("buffer is zeroed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	if !b.IsAlive() {
		t.Error("buffer should not be destroyed")
	}
	b.Destroy()
	b = NewBufferRandom(0)
	if b.Bytes() != nil {
		t.Error("data slice should be nil")
	}
	if b.Size() != 0 {
		t.Error("size should be zero", b.Size())
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestFreeze(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("buffer is nil")
	}
	if !b.IsMutable() {
		t.Error("buffer isn't mutable")
	}
	b.Freeze()
	if b.IsMutable() {
		t.Error("buffer did not change to immutable")
	}
	if !bytes.Equal(b.Bytes(), make([]byte, 8)) {
		t.Error("buffer changed value") // also tests readability
	}
	b.Freeze() // Test idempotency
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	if !bytes.Equal(b.Bytes(), make([]byte, 8)) {
		t.Error("buffer changed value") // also tests readability
	}
	b.Destroy()
	b.Freeze()
	if b.IsMutable() {
		t.Error("buffer is mutable")
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Freeze()
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestMelt(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("buffer is nil")
	}
	b.Freeze()
	if b.IsMutable() {
		t.Error("buffer is mutable")
	}
	b.Melt()
	if !b.IsMutable() {
		t.Error("buffer did not become mutable")
	}
	if !bytes.Equal(b.Bytes(), make([]byte, 8)) {
		t.Error("buffer changed value") // also tests readability
	}
	b.Bytes()[0] = 0x1 // test writability
	if b.Bytes()[0] != 0x1 {
		t.Error("buffer value not changed")
	}
	b.Melt() // Test idempotency
	if !b.IsMutable() {
		t.Error("buffer should be mutable")
	}
	b.Bytes()[0] = 0x2
	if b.Bytes()[0] != 0x2 {
		t.Error("buffer value not changed")
	}
	b.Destroy()
	b.Melt()
	if b.IsMutable() {
		t.Error("buffer shouldn't be mutable")
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Melt()
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestSeal(t *testing.T) {
	b := NewBufferRandom(32)
	if b == nil {
		t.Error("buffer is nil")
	}
	data := make([]byte, 32)
	copy(data, b.Bytes())
	e := b.Seal()
	if e == nil {
		t.Error("got nil enclave")
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	b, err := e.Open()
	if err != nil {
		t.Error("unexpected error;", err)
	}
	if !bytes.Equal(b.Bytes(), data) {
		t.Error("data does not match")
	}
	b.Destroy()
	e = b.Seal() // call on destroyed buffer
	if e != nil {
		t.Error("expected nil enclave")
	}
}

func TestCopy(t *testing.T) {
	b := NewBuffer(16)
	if b == nil {
		t.Error("buffer is nil")
	}
	b.Copy([]byte("yellow submarine"))
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("copy unsuccessful")
	}
	b.Destroy()
	b.Copy([]byte("yellow submarine"))
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Copy([]byte("yellow submarine"))
}

func TestCopyAt(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("got nil buffer")
	}
	b.CopyAt(0, []byte("1234"))
	if !bytes.Equal(b.Bytes()[:4], []byte("1234")) {
		t.Error("copy unsuccessful")
	}
	if !bytes.Equal(b.Bytes()[4:], []byte{0, 0, 0, 0}) {
		t.Error("copy overflow")
	}
	b.CopyAt(4, []byte("5678"))
	if !bytes.Equal(b.Bytes(), []byte("12345678")) {
		t.Error("copy unsuccessful")
	}
	b.Destroy()
	b.CopyAt(4, []byte("hmmm"))
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.CopyAt(4, []byte("yellow submarine"))
}

func TestMove(t *testing.T) {
	b := NewBuffer(16)
	if b == nil {
		t.Error("buffer is nil")
	}
	b.Move([]byte("yellow submarine"))
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("copy unsuccessful")
	}
	data := []byte("yellow submarine")
	b.Move(data)
	for b := range data {
		if data[b] != 0x0 {
			t.Error("buffer was not wiped", b)
		}
	}
	b.Destroy()
	b.Move(data)
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Move([]byte("yellow submarine"))
}

func TestMoveAt(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("got nil buffer")
	}
	data := []byte("12345678")
	b.MoveAt(0, data[:4])
	if !bytes.Equal(b.Bytes()[:4], []byte("1234")) {
		t.Error("copy unsuccessful")
	}
	if !bytes.Equal(b.Bytes()[4:], []byte{0, 0, 0, 0}) {
		t.Error("copy overflow")
	}
	b.MoveAt(4, data[4:])
	if !bytes.Equal(b.Bytes(), []byte("12345678")) {
		t.Error("copy unsuccessful")
	}
	if !bytes.Equal(data, make([]byte, 8)) {
		t.Error("buffer not wiped")
	}
	b.Destroy()
	b.MoveAt(4, []byte("hmmm"))
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.MoveAt(4, []byte("yellow submarine"))
}

func TestScramble(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("buffer is nil")
	}
	b.Scramble()
	if bytes.Equal(b.Bytes(), make([]byte, 32)) {
		t.Error("buffer was not randomised")
	}
	one := make([]byte, 32)
	copy(one, b.Bytes())
	b.Scramble()
	if bytes.Equal(b.Bytes(), make([]byte, 32)) {
		t.Error("buffer was not randomised")
	}
	if bytes.Equal(b.Bytes(), one) {
		t.Error("buffer did not change")
	}
	b.Destroy()
	b.Scramble()
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Scramble()
}

func TestWipe(t *testing.T) {
	b := NewBufferRandom(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	b.Melt()
	if bytes.Equal(b.Bytes(), make([]byte, 32)) {
		t.Error("buffer was not randomised")
	}
	b.Wipe()
	for i := range b.Bytes() {
		if b.Bytes()[i] != 0 {
			t.Error("buffer was not wiped; index", i)
		}
	}
	b.Destroy()
	b.Wipe()
	if b.Bytes() != nil {
		t.Error("buffer should be destroyed")
	}
	b = newNullBuffer()
	b.Wipe()
}

func TestSize(t *testing.T) {
	b := NewBuffer(1234)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.Size() != 1234 {
		t.Error("size does not match expected")
	}
	b.Destroy()
	if b.Size() != 0 {
		t.Error("destroyed buffer size should be zero")
	}
	b = newNullBuffer()
	if b.Size() != 0 {
		t.Error("size should be zero")
	}
}

func TestDestroy(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.Bytes() == nil {
		t.Error("expected buffer to not be nil")
	}
	if len(b.Bytes()) != 32 || cap(b.Bytes()) != 32 {
		t.Error("buffer sizes incorrect")
	}
	if !b.IsAlive() {
		t.Error("buffer should be alive")
	}
	if !b.IsMutable() {
		t.Error("buffer should be mutable")
	}
	b.Destroy()
	if b.Bytes() != nil {
		t.Error("expected buffer to be nil")
	}
	if len(b.Bytes()) != 0 || cap(b.Bytes()) != 0 {
		t.Error("buffer sizes incorrect")
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b.Destroy()
	if b.Bytes() != nil {
		t.Error("expected buffer to be nil")
	}
	if len(b.Bytes()) != 0 || cap(b.Bytes()) != 0 {
		t.Error("buffer sizes incorrect")
	}
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
	b = newNullBuffer()
	b.Destroy()
	if b.IsAlive() {
		t.Error("buffer should be dead")
	}
}

func TestIsAlive(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("got nil buffer")
	}
	if !b.IsAlive() {
		t.Error("invalid state")
	}
	if b.IsAlive() != b.IsAlive() {
		t.Error("states don't match")
	}
	b.Destroy()
	if b.IsAlive() {
		t.Error("invalid state")
	}
	if b.IsAlive() != b.IsAlive() {
		t.Error("states don't match")
	}
	b = newNullBuffer()
	if b.IsAlive() {
		t.Error("buffer should be dead")
	}
}

func TestIsMutable(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("got nil buffer")
	}
	if !b.IsMutable() {
		t.Error("invalid state")
	}
	if b.IsMutable() != b.IsMutable() {
		t.Error("states don't match")
	}
	b.Freeze()
	if b.IsMutable() {
		t.Error("invalid state")
	}
	if b.IsMutable() != b.IsMutable() {
		t.Error("states don't match")
	}
	b.Destroy()
	if b.IsMutable() {
		t.Error("invalid state")
	}
	if b.IsMutable() != b.IsMutable() {
		t.Error("states don't match")
	}
	b = newNullBuffer()
	if b.IsMutable() {
		t.Error("buffer should be immutable")
	}
}

func TestEqualTo(t *testing.T) {
	b := NewBufferFromBytes([]byte("yellow submarine"))
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("comparison incorrect")
	}
	if b.EqualTo([]byte("yellow")) {
		t.Error("comparison incorrect")
	}
	b.Destroy()
	if b.EqualTo([]byte("yellow submarine")) {
		t.Error("comparison with destroyed should be false")
	}
	b = newNullBuffer()
	if !b.EqualTo([]byte{}) {
		t.Error("buffer should be size zero")
	}
}

func TestBytes(t *testing.T) {
	b := NewBufferFromBytes([]byte("yellow submarine"))
	if b == nil {
		t.Error("got nil buffer")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("not equal contents")
	}
	b.Melt()
	b.Bytes()[8] = ^b.Bytes()[8]
	if !bytes.Equal(b.Buffer.Data(), b.Bytes()) {
		t.Error("methods disagree")
	}
	b.Destroy()
	if b.Bytes() != nil {
		t.Error("expected nil buffer")
	}
	b = newNullBuffer()
	if b.Bytes() != nil {
		t.Error("buffer should be nil")
	}
}

func TestReader(t *testing.T) {
	b := NewBufferRandom(32)
	c, err := NewBufferFromReader(b.Reader(), 32)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b.Bytes(), c.Bytes()) {
		t.Error("data not equal")
	}
	b.Destroy()
	c.Destroy()
	if c.Reader().Size() != 0 {
		t.Error("expected nul reader")
	}
	b = newNullBuffer()
	if c.Reader().Size() != 0 {
		t.Error("expected nul reader")
	}
}

func TestString(t *testing.T) {
	b := NewBufferFromBytes([]byte("yellow submarine"))
	s := b.String()
	if s != "yellow submarine" {
		t.Error("string content mismatch")
	}
	// Mutating the buffer must not change the snapshot.
	b.Melt()
	for i := range b.Bytes() {
		b.Bytes()[i] = 'x'
	}
	if s != "yellow submarine" {
		t.Error("string aliases locked memory; expected a copy")
	}
	b.Destroy()
	s = b.String()
	if s != "" {
		t.Error("string should be empty")
	}
	b = newNullBuffer()
	if b.String() != "" {
		t.Error("string should be empty")
	}
}

func TestUint16(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	u16 := b.Uint16()
	if len(u16) != 16 || cap(u16) != 16 {
		t.Error("sizes incorrect")
	}
	u16[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(3)
	if b == nil {
		t.Error("got nil buffer")
	}
	u16 = b.Uint16()
	if len(u16) != 1 || cap(u16) != 1 {
		t.Error("sizes should be 1")
	}
	u16[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(1)
	if b == nil {
		t.Error("got nil buffer")
	}
	u16 = b.Uint16()
	if u16 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Uint16() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Uint16() != nil {
		t.Error("should be nil")
	}
}

func TestUint32(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	u32 := b.Uint32()
	if len(u32) != 8 || cap(u32) != 8 {
		t.Error("sizes incorrect")
	}
	u32[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(5)
	if b == nil {
		t.Error("got nil buffer")
	}
	u32 = b.Uint32()
	if len(u32) != 1 || cap(u32) != 1 {
		t.Error("sizes should be 1")
	}
	u32[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(3)
	if b == nil {
		t.Error("got nil buffer")
	}
	u32 = b.Uint32()
	if u32 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Uint32() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Uint32() != nil {
		t.Error("should be nil")
	}
}

func TestUint64(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	u64 := b.Uint64()
	if len(u64) != 4 || cap(u64) != 4 {
		t.Error("sizes incorrect")
	}
	u64[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(9)
	if b == nil {
		t.Error("got nil buffer")
	}
	u64 = b.Uint64()
	if len(u64) != 1 || cap(u64) != 1 {
		t.Error("sizes should be 1")
	}
	u64[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(7)
	if b == nil {
		t.Error("got nil buffer")
	}
	u64 = b.Uint64()
	if u64 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Uint64() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Uint64() != nil {
		t.Error("should be nil")
	}
}

func TestInt8(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	i8 := b.Int8()
	if len(i8) != 32 || cap(i8) != 32 {
		t.Error("sizes incorrect")
	}
	i8[0] ^= 0x7f
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	if b.Int8() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Int8() != nil {
		t.Error("should be nil")
	}
}

func TestInt16(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	i16 := b.Int16()
	if len(i16) != 16 || cap(i16) != 16 {
		t.Error("sizes incorrect")
	}
	i16[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(3)
	if b == nil {
		t.Error("got nil buffer")
	}
	i16 = b.Int16()
	if len(i16) != 1 || cap(i16) != 1 {
		t.Error("sizes should be 1")
	}
	i16[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(1)
	if b == nil {
		t.Error("got nil buffer")
	}
	i16 = b.Int16()
	if i16 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Int16() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Int16() != nil {
		t.Error("should be nil")
	}
}

func TestInt32(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	i32 := b.Int32()
	if len(i32) != 8 || cap(i32) != 8 {
		t.Error("sizes incorrect")
	}
	i32[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(5)
	if b == nil {
		t.Error("got nil buffer")
	}
	i32 = b.Int32()
	if len(i32) != 1 || cap(i32) != 1 {
		t.Error("sizes should be 1")
	}
	i32[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(3)
	if b == nil {
		t.Error("got nil buffer")
	}
	i32 = b.Int32()
	if i32 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Int32() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Int32() != nil {
		t.Error("should be nil")
	}
}

func TestInt64(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	i64 := b.Int64()
	if len(i64) != 4 || cap(i64) != 4 {
		t.Error("sizes incorrect")
	}
	i64[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(9)
	if b == nil {
		t.Error("got nil buffer")
	}
	i64 = b.Int64()
	if len(i64) != 1 || cap(i64) != 1 {
		t.Error("sizes should be 1")
	}
	i64[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("view aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(7)
	if b == nil {
		t.Error("got nil buffer")
	}
	i64 = b.Int64()
	if i64 != nil {
		t.Error("expected nil slice")
	}
	b.Destroy()
	if b.Int64() != nil {
		t.Error("expected nil slice as buffer destroyed")
	}
	b = newNullBuffer()
	if b.Int32() != nil {
		t.Error("should be nil")
	}
}

func TestByteArray8(t *testing.T) {
	b := NewBuffer(8)
	if b == nil {
		t.Error("got nil buffer")
	}
	a := b.ByteArray8()
	if a == nil {
		t.Fatal("expected byte array")
	}
	a[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("array aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(7)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.ByteArray8() != nil {
		t.Error("expected nil byte array")
	}
	b.Destroy()
	if b.ByteArray8() != nil {
		t.Error("expected nil byte array from destroyed buffer")
	}
	b = newNullBuffer()
	if b.ByteArray8() != nil {
		t.Error("should be nil")
	}
}

func TestByteArray16(t *testing.T) {
	b := NewBuffer(16)
	if b == nil {
		t.Error("got nil buffer")
	}
	a := b.ByteArray16()
	if a == nil {
		t.Fatal("expected byte array")
	}
	a[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("array aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(15)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.ByteArray16() != nil {
		t.Error("expected nil byte array")
	}
	b.Destroy()
	if b.ByteArray16() != nil {
		t.Error("expected nil byte array from destroyed buffer")
	}
	b = newNullBuffer()
	if b.ByteArray16() != nil {
		t.Error("should be nil")
	}
}

func TestByteArray32(t *testing.T) {
	b := NewBuffer(32)
	if b == nil {
		t.Error("got nil buffer")
	}
	a := b.ByteArray32()
	if a == nil {
		t.Fatal("expected byte array")
	}
	a[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("array aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(31)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.ByteArray32() != nil {
		t.Error("expected nil byte array")
	}
	b.Destroy()
	if b.ByteArray32() != nil {
		t.Error("expected nil byte array from destroyed buffer")
	}
	b = newNullBuffer()
	if b.ByteArray32() != nil {
		t.Error("should be nil")
	}
}

func TestByteArray64(t *testing.T) {
	b := NewBuffer(64)
	if b == nil {
		t.Error("got nil buffer")
	}
	a := b.ByteArray64()
	if a == nil {
		t.Fatal("expected byte array")
	}
	a[0] ^= 0xff
	if !bytes.Equal(b.Bytes(), make([]byte, b.Size())) {
		t.Error("array aliases locked memory; expected a copy")
	}
	b.Destroy()
	b = NewBuffer(63)
	if b == nil {
		t.Error("got nil buffer")
	}
	if b.ByteArray64() != nil {
		t.Error("expected nil byte array")
	}
	b.Destroy()
	if b.ByteArray64() != nil {
		t.Error("expected nil byte array from destroyed buffer")
	}
	b = newNullBuffer()
	if b.ByteArray64() != nil {
		t.Error("should be nil")
	}
}

func TestTypedViewCopies(t *testing.T) {
	pattern := make([]byte, 64)
	for i := range pattern {
		pattern[i] = byte(i*3 + 1)
	}
	b := NewBuffer(64)
	b.Copy(pattern)

	i8 := b.Int8()
	if len(i8) != 64 {
		t.Fatal("sizes incorrect")
	}
	for i := range i8 {
		if byte(i8[i]) != pattern[i] {
			t.Fatal("int8 content mismatch")
		}
	}
	if got := b.Uint16(); len(got) != 32 || got[0] != nativeOrder.Uint16(pattern[:2]) {
		t.Error("uint16 content mismatch")
	}
	if got := b.Uint32(); len(got) != 16 || got[0] != nativeOrder.Uint32(pattern[:4]) {
		t.Error("uint32 content mismatch")
	}
	if got := b.Uint64(); len(got) != 8 || got[0] != nativeOrder.Uint64(pattern[:8]) {
		t.Error("uint64 content mismatch")
	}
	if got := b.Int16(); len(got) != 32 || got[0] != int16(nativeOrder.Uint16(pattern[:2])) {
		t.Error("int16 content mismatch")
	}
	if got := b.Int32(); len(got) != 16 || got[0] != int32(nativeOrder.Uint32(pattern[:4])) {
		t.Error("int32 content mismatch")
	}
	if got := b.Int64(); len(got) != 8 || got[0] != int64(nativeOrder.Uint64(pattern[:8])) {
		t.Error("int64 content mismatch")
	}
	if s := b.String(); s != string(pattern) {
		t.Error("string content mismatch")
	}
	if a := b.ByteArray8(); a == nil || *a != [8]byte(pattern[:8]) {
		t.Error("bytearray8 content mismatch")
	}
	if a := b.ByteArray16(); a == nil || *a != [16]byte(pattern[:16]) {
		t.Error("bytearray16 content mismatch")
	}
	if a := b.ByteArray32(); a == nil || *a != [32]byte(pattern[:32]) {
		t.Error("bytearray32 content mismatch")
	}
	if a := b.ByteArray64(); a == nil || *a != [64]byte(pattern) {
		t.Error("bytearray64 content mismatch")
	}

	// Detach: destroying the buffer leaves all copies intact.
	u := b.Uint64()
	a := b.ByteArray32()
	s := b.String()
	b.Destroy()
	if u[0] != nativeOrder.Uint64(pattern[:8]) || *a != [32]byte(pattern[:32]) || s != string(pattern) {
		t.Error("copies did not survive destroy")
	}
}

func TestCopyOverflowPanics(t *testing.T) {
	b := NewBuffer(8)
	if !panics(func() { b.Copy(make([]byte, 9)) }) {
		t.Error("expected panic on copy overflow")
	}
	if !panics(func() { b.CopyAt(4, make([]byte, 5)) }) {
		t.Error("expected panic on copyat overflow")
	}
	if !panics(func() { b.CopyAt(9, []byte{1}) }) {
		t.Error("expected panic on offset out of range")
	}
	if !panics(func() { b.CopyAt(-1, []byte{1}) }) {
		t.Error("expected panic on negative offset")
	}
	// Exact fits are fine.
	b.Copy(make([]byte, 8))
	b.CopyAt(8, []byte{})
	if !panics(func() { b.Move(make([]byte, 9)) }) {
		t.Error("expected panic on move overflow")
	}
	if !panics(func() { b.MoveAt(4, make([]byte, 5)) }) {
		t.Error("expected panic on moveat overflow")
	}
	// Dead buffers stay silent, never panic.
	b.Destroy()
	b.Copy(make([]byte, 99))
	b.MoveAt(99, make([]byte, 99))
	nb := newNullBuffer()
	nb.CopyAt(4, make([]byte, 99))
}

func TestWithBytes(t *testing.T) {
	b := NewBufferFromBytes([]byte("yellow submarine"))
	var seen []byte
	b.WithBytes(func(v []byte) {
		seen = append([]byte{}, v...)
		if !bytes.Equal(v, []byte("yellow submarine")) {
			t.Error("view content mismatch")
		}
	})
	if !bytes.Equal(seen, []byte("yellow submarine")) {
		t.Error("callback did not run")
	}
	b.Destroy()
	called := false
	b.WithBytes(func([]byte) { called = true })
	if called {
		t.Error("callback must not run on destroyed buffer")
	}
	nb := newNullBuffer()
	nb.WithBytes(func([]byte) { called = true })
	if called {
		t.Error("callback must not run on null buffer")
	}
}
