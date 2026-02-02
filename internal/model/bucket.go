package model

import (
	"errors"
	"time"
)

var (
	// ErrBucketFull is returned when the amount requested to add exceeds the remaining space in the bucket.
	ErrBucketFull = errors.New("add exceeds free bucket capacity")
)

// Bucket interface for interacting with leaky buckets: https://en.wikipedia.org/wiki/Leaky_bucket
// Underlying mechanism does not implement Leaky_bucket algorithm :'(
type Bucket interface {
	// Capacity of the bucket.
	Capacity() uint

	// Remaining space in the bucket.
	Remaining() uint

	// Reset returns when the bucket will be drained.
	Reset() time.Time

	// Add to the bucket. Returns bucket state after adding.
	Add(uint) (BucketState, error)

	// State returns bucket state.
	State() BucketState
}

// BucketState is a snapshot of a bucket's properties.
type BucketState struct {
	Capacity  uint
	Remaining uint
	Reset     time.Time
}

// BucketStorage interface for generating buckets keyed by a string.
type BucketStorage interface {
	// Create a bucket with a name, capacity, and rate.
	// rate is how long it takes for full capacity to drain.
	Create(name string, capacity uint, rate time.Duration) (Bucket, error)
}
