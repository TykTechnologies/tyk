package pool

import (
	"hash"
	"sync"

	"github.com/cespare/xxhash"
)

var (
	Hash64 = hash64Pool{
		pool: sync.Pool{
			New: func() interface{} {
				return xxhash.New()
			},
		},
	}
)

type hash64Pool struct {
	pool sync.Pool
}

func (b *hash64Pool) Get() hash.Hash64 {
	return b.pool.Get().(hash.Hash64)
}

func (b *hash64Pool) Put(hash64 hash.Hash64) {
	hash64.Reset()
	b.pool.Put(hash64)
}
