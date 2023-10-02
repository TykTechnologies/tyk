package httputil

import (
	"net/http/httputil"
	"sync"
)

// BufferPool is an interface for temporary buffer allocations.
type BufferPool = httputil.BufferPool

// NewSyncBufferPool creates a BufferPool backed with a sync.Pool.
func NewSyncBufferPool(size int) *SyncBufferPool {
	return &SyncBufferPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

// SyncBufferPool is a sync.Pool backed BufferPool.
type SyncBufferPool struct {
	pool sync.Pool
}

// Get returns a slice to be used for buffering.
func (b *SyncBufferPool) Get() []byte {
	return b.pool.Get().([]byte)
}

// Put releases a slice that was used for buffering.
func (b *SyncBufferPool) Put(buf []byte) {
	b.pool.Put(buf)
}

// Assert that we implement the BufferPool interface.
var _ BufferPool = &SyncBufferPool{}
