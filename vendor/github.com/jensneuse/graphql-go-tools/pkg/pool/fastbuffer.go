package pool

import (
	"sync"

	"github.com/jensneuse/graphql-go-tools/pkg/fastbuffer"
)

var FastBuffer = fastBufferPool{
	pool: sync.Pool{
		New: func() interface{} {
			return fastbuffer.New()
		},
	},
}

type fastBufferPool struct {
	pool sync.Pool
}

func (f *fastBufferPool) Get() *fastbuffer.FastBuffer {
	return f.pool.Get().(*fastbuffer.FastBuffer)
}

func (f *fastBufferPool) Put(buf *fastbuffer.FastBuffer) {
	buf.Reset()
	f.pool.Put(buf)
}
