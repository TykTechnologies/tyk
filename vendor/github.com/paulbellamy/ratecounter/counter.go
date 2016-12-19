package ratecounter

import "sync/atomic"

// A Counter is a thread-safe counter implementation
type Counter int64

// Increment the counter by some value
func (c *Counter) Incr(val int64) {
	atomic.AddInt64((*int64)(c), val)
}

// Return the counter's current value
func (c *Counter) Value() int64 {
	return atomic.LoadInt64((*int64)(c))
}
