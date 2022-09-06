package pool

import (
	"bytes"
	"sync"
)

var (
	BytesBuffer = bytesBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 1024))
			},
		},
	}
)

type bytesBufferPool struct {
	pool sync.Pool
}

func (b *bytesBufferPool) Get() *bytes.Buffer {
	return b.pool.Get().(*bytes.Buffer)
}

func (b *bytesBufferPool) Put(buf *bytes.Buffer) {
	buf.Reset()
	b.pool.Put(buf)
}
