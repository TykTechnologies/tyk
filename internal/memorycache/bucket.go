package memorycache

import (
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
)

type Bucket struct {
	capacity  uint
	remaining uint
	reset     time.Time
	rate      time.Duration
	mutex     sync.Mutex
}

func (b *Bucket) Capacity() uint {
	return b.capacity
}

// Remaining space in the bucket.
func (b *Bucket) Remaining() uint {
	return b.remaining
}

// Reset returns when the bucket will be drained.
func (b *Bucket) Reset() time.Time {
	return b.reset
}

// Add to the bucket.
func (b *Bucket) Add(amount uint) (model.BucketState, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if time.Now().After(b.reset) {
		b.reset = time.Now().Add(b.rate)
		b.remaining = b.capacity
	}
	if amount > b.remaining {
		return model.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, model.ErrBucketFull
	}
	b.remaining -= amount
	return model.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, nil
}
