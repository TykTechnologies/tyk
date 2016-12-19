package memorycache

import (
	"sync"
	"time"

	"github.com/TykTechnologies/leakybucket"
)

type bucket struct {
	capacity  uint
	remaining uint
	reset     time.Time
	rate      time.Duration
	mutex     sync.Mutex
}

func (b *bucket) Capacity() uint {
	return b.capacity
}

// Remaining space in the bucket.
func (b *bucket) Remaining() uint {
	return b.remaining
}

// Reset returns when the bucket will be drained.
func (b *bucket) Reset() time.Time {
	return b.reset
}

// Add to the bucket.
func (b *bucket) Add(amount uint) (leakybucket.BucketState, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if time.Now().After(b.reset) {
		b.reset = time.Now().Add(b.rate)
		b.remaining = b.capacity
	}
	if amount > b.remaining {
		return leakybucket.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, leakybucket.ErrorFull
	}
	b.remaining -= amount
	return leakybucket.BucketState{Capacity: b.capacity, Remaining: b.remaining, Reset: b.reset}, nil
}

// Storage is a non thread-safe in-memory leaky bucket factory.
type Storage struct {
	buckets *Cache
}

// New initializes the in-memory bucket store.
func New() *Storage {
	return &Storage{
		buckets: NewCache(10 * time.Minute),
	}
}

// Create a bucket.
func (s *Storage) Create(name string, capacity uint, rate time.Duration) (leakybucket.Bucket, error) {
	b, ok := s.buckets.Get(name)
	if ok {
		return b, nil
	}

	b = &bucket{
		capacity:  capacity,
		remaining: capacity,
		reset:     time.Now().Add(rate),
		rate:      rate,
	}
	s.buckets.Set(name, b)
	return b, nil
}
