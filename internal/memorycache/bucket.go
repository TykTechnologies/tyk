package memorycache

import (
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
)

var (
	_ model.Bucket = new(Bucket)
)

type Bucket struct {
	capacity  uint
	remaining uint
	reset     time.Time
	rate      time.Duration
	mutex     sync.Mutex
}

func NewBucket(capacity uint, rate time.Duration) *Bucket {
	return &Bucket{
		capacity:  capacity,
		remaining: capacity,
		reset:     time.Now().Add(rate),
		rate:      rate,
	}
}

// Add to the bucket.
func (b *Bucket) Add(amount uint) (model.BucketState, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.resetIfNeeded()
	if amount > b.remaining {
		return model.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, model.ErrBucketFull
	}
	b.remaining -= amount
	return model.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, nil
}

// State returns bucket state.
func (b *Bucket) State() model.BucketState {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.resetIfNeeded()

	return model.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}
}

func (b *Bucket) resetIfNeeded() {
	if time.Now().After(b.reset) {
		b.reset = time.Now().Add(b.rate)
		b.remaining = b.capacity
	}
}
