package redeo

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"sync"
)

const (
	codeInline  = '+'
	codeError   = '-'
	codeFixnum  = ':'
	codeStrLen  = '$'
	codeBulkLen = '*'
)

var (
	binCRLF = []byte("\r\n")
	binOK   = []byte("+OK\r\n")
	binZERO = []byte(":0\r\n")
	binONE  = []byte(":1\r\n")
	binNIL  = []byte("$-1\r\n")
)

var bufferPool sync.Pool

// Responder generates client responses
type Responder struct {
	w io.Writer

	buf *bytes.Buffer
	err error
}

// NewResponder creates a new responder instance
func NewResponder(w io.Writer) *Responder {
	var buf *bytes.Buffer
	if v := bufferPool.Get(); v != nil {
		buf = v.(*bytes.Buffer)
		buf.Reset()
	} else {
		buf = new(bytes.Buffer)
	}

	return &Responder{w: w, buf: buf}
}

// WriteBulkLen writes a bulk length
func (r *Responder) WriteBulkLen(n int) {
	r.writeInline(codeBulkLen, strconv.Itoa(n))
}

// WriteBulk writes a slice
func (r *Responder) WriteBulk(bulk [][]byte) {
	if r.err != nil {
		return
	}

	r.WriteBulkLen(len(bulk))
	for _, b := range bulk {
		if b == nil {
			r.WriteNil()
		} else {
			r.WriteBytes(b)
		}
	}
}

// WriteStringBulk writes a string slice
func (r *Responder) WriteStringBulk(bulk []string) {
	if r.err != nil {
		return
	}

	r.WriteBulkLen(len(bulk))
	for _, b := range bulk {
		r.WriteString(b)
	}
}

// WriteString writes a bulk string
func (r *Responder) WriteString(s string) {
	if r.err != nil {
		return
	}

	if err := r.buf.WriteByte(codeStrLen); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.WriteString(strconv.Itoa(len(s))); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.WriteString(s); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
}

// WriteBytes writes a bulk string
func (r *Responder) WriteBytes(b []byte) {
	if r.err != nil {
		return
	}

	if err := r.buf.WriteByte(codeStrLen); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.WriteString(strconv.Itoa(len(b))); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(b); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
}

// WriteString writes an inline string
func (r *Responder) WriteInlineString(s string) {
	r.writeInline(codeInline, s)
}

// WriteNil writes a nil value
func (r *Responder) WriteNil() {
	r.writeRaw(binNIL)
}

// WriteOK writes OK
func (r *Responder) WriteOK() {
	r.writeRaw(binOK)
}

// WriteInt writes an inline integer
func (r *Responder) WriteInt(n int) {
	r.writeInline(codeFixnum, strconv.Itoa(n))
}

// WriteZero writes a 0 integer
func (r *Responder) WriteZero() {
	r.writeRaw(binZERO)
}

// WriteOne writes a 1 integer
func (r *Responder) WriteOne() {
	r.writeRaw(binONE)
}

// WriteErrorString writes an error string
func (r *Responder) WriteErrorString(s string) {
	r.writeInline(codeError, s)
}

// WriteError writes an error using the standard "ERR message" format
func (r *Responder) WriteError(err error) {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > -1 {
		s = s[i+2:]
	}
	r.WriteErrorString("ERR " + s)
}

// WriteN streams data from a reader
func (r *Responder) WriteN(rd io.Reader, n int64) {
	if r.err != nil {
		return
	}

	if err := r.buf.WriteByte(codeStrLen); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.WriteString(strconv.FormatInt(n, 10)); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
	if err := r.Flush(); err != nil {
		return
	}
	if _, err := io.CopyN(r.w, rd, n); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
}

func (r *Responder) Flush() error {
	if r.err == nil {
		_, r.err = io.Copy(r.w, r.buf)
		r.buf.Reset()
	}
	return r.err
}

// ------------------------------------------------------------------------

func (r *Responder) release() error {
	err := r.Flush()
	bufferPool.Put(r.buf)
	return err
}

func (r *Responder) writeInline(prefix byte, s string) {
	if r.err != nil {
		return
	}

	if err := r.buf.WriteByte(prefix); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.WriteString(s); err != nil {
		r.err = err
		return
	}
	if _, err := r.buf.Write(binCRLF); err != nil {
		r.err = err
		return
	}
}

func (r *Responder) writeRaw(p []byte) {
	if r.err != nil {
		return
	}
	if _, err := r.buf.Write(p); err != nil {
		r.err = err
		return
	}
}
