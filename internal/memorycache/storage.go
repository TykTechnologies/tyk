package memorycache

import (
	"context"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
)

// BucketStorage is a non thread-safe in-memory leaky bucket factory.
type BucketStorage struct {
	buckets *Cache
}

// New initializes the in-memory bucket store.
func New(ctx context.Context) *BucketStorage {
	return &BucketStorage{
		buckets: NewCache(ctx, 10*time.Minute),
	}
}

// Create a bucket.
func (s *BucketStorage) Create(name string, capacity uint, rate time.Duration) (model.Bucket, error) {
	b, ok := s.buckets.Get(name)
	if ok {
		return b, nil
	}

	b = &Bucket{
		capacity:  capacity,
		remaining: capacity,
		reset:     time.Now().Add(rate),
		rate:      rate,
	}
	s.buckets.Set(name, b)
	return b, nil
}
