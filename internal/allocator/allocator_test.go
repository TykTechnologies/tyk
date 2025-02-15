package allocator

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/allocator/mock"
)

func TestAllocator(t *testing.T) {
	alloc := New[mock.Document](mock.NewDocument)

	// Get an object.
	obj := alloc.Get()
	assert.Len(t, obj.Tags, 0)
}

func BenchmarkConstructor(b *testing.B) {
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			obj := mock.NewDocument()
			assert.NotNil(b, obj)
			i++

			if i&0xffff == 0 {
				runtime.GC()
			}
		}
	})
}

func BenchmarkAllocator(b *testing.B) {
	alloc := New[mock.Document](mock.NewDocument)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			obj := alloc.Get()
			assert.NotNil(b, obj)
			alloc.Put(obj)
			i++

			if i&0xffff == 0 {
				runtime.GC()
			}
		}
	})
}
