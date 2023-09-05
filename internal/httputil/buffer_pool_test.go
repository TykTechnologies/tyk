package httputil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSyncBufferPool(t *testing.T) {
	pool := NewSyncBufferPool(1024)

	item := pool.Get()
	assert.Len(t, item, 1024)

	pool.Put(item)
}
