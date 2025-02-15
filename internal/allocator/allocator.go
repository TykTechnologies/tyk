package allocator

import (
	"sync"
)

// Reseter is the interface that types must implement to be managed by Allocator.
type Reseter interface {
	Reset()
}

// Allocator holds a sync.Pool of objects of type T.
type Allocator[T any] struct {
	pool sync.Pool
}

// New creates an Allocator for type T using the provided constructor.
func New[T any](newFunc func() *T) *Allocator[T] {
	return &Allocator[T]{
		pool: sync.Pool{
			New: func() any {
				return newFunc()
			},
		},
	}
}

// Get retrieves an object from the pool or creates a new one via newFunc.
func (a *Allocator[T]) Get() *T {
	return a.pool.Get().(*T)
}

// put returns an object to the pool after resetting it and removing its finalizer.
func (a *Allocator[T]) Put(t *T) {
	reset(t)
	a.pool.Put(t)
}

// reset calls a .Reset method on the provided argument, if matching.
func reset(t any) {
	reset, ok := t.(Reseter)
	if ok {
		reset.Reset()
	}
}
