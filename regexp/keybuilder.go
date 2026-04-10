package regexp

import (
	"fmt"
	"strconv"
	"sync"
	"unsafe"
)

var keyBuilderPool = sync.Pool{
	New: func() interface{} { return new(keyBuilder) },
}

// Combine logic of strings.Builder and bytes.Buffer.
// Allow to reuse builder with 0 allocs, as bytes.Buffer
// and also allow to get 0 alloc string representation
// as strings.Builder
type keyBuilder struct {
	buf []byte
}

// Reset resets the keyBuilder to be empty.
func (kb *keyBuilder) Reset() *keyBuilder {
	kb.buf = kb.buf[:0]
	return kb
}

// Returns content of internal buffer, converted to string.
// Safe for using as key for storing item, immutable
func (kb *keyBuilder) Key() string {
	return string(kb.buf)
}

// Returns string representation of internal buffer.
// Mutable, sequential writes to keyBuilder will
// also mutate returned representation.
// Safe for lookups by key.
// Should not be used as key for storing items.
func (kb *keyBuilder) UnsafeKey() string {
	return *(*string)(unsafe.Pointer(&kb.buf))
}

func (kb *keyBuilder) Write(p []byte) (int, error) {
	kb.buf = append(kb.buf, p...)
	return len(p), nil
}

func (kb *keyBuilder) AppendString(s string) *keyBuilder {
	kb.buf = append(kb.buf, s...)
	return kb
}

func (kb *keyBuilder) AppendBytes(b []byte) *keyBuilder {
	kb.buf = append(kb.buf, b...)
	return kb
}

func (kb *keyBuilder) Appendf(format string, a ...interface{}) *keyBuilder {
	fmt.Fprintf(kb, format, a...)
	return kb
}

func (kb *keyBuilder) AppendInt(n int) *keyBuilder {
	kb.buf = strconv.AppendInt(kb.buf, int64(n), 10)
	return kb
}
