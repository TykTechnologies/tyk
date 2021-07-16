package buffers

import (
	"bufio"
	"bytes"
	"sync"

	"mosn.io/proxy-wasm-go-host/proxywasm/common"
)

var pool = &sync.Pool{
	New: func() interface{} { return new(IO) },
}

var _ common.IoBuffer = (*IO)(nil)

type IO struct {
	buf *bytes.Buffer
	*bufio.Reader
}

func New() *IO {
	buf := new(bytes.Buffer)
	return &IO{
		buf:    buf,
		Reader: bufio.NewReader(buf),
	}
}

func (h *IO) Bytes() []byte {
	return h.Bytes()
}

func (h *IO) Write(p []byte) (int, error) {
	return h.buf.Write(p)
}

func (h *IO) Len() int { return h.buf.Len() }

func (h *IO) Reset() {
	h.buf.Reset()
	h.Reader.Reset(h.buf)
}

func (h *IO) Drain(offset int) {}

func (*IO) Close() error { return nil }

func Get() *IO {
	return pool.Get().(*IO)
}

func Put(bufs ...*IO) {
	for _, io := range bufs {
		io.Reset()
		pool.Put(io)
	}
}
