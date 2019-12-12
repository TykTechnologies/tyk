package ratecounter

import (
	"strconv"
	"time"
)

// An AvgRateCounter is a thread-safe counter which returns
// the ratio between the number of calls 'Incr' and the counter value in the last interval
type AvgRateCounter struct {
	hits     *RateCounter
	counter  *RateCounter
	interval time.Duration
}

// NewAvgRateCounter constructs a new AvgRateCounter, for the interval provided
func NewAvgRateCounter(intrvl time.Duration) *AvgRateCounter {
	return &AvgRateCounter{
		hits:     NewRateCounter(intrvl),
		counter:  NewRateCounter(intrvl),
		interval: intrvl,
	}
}

// WithResolution determines the minimum resolution of this counter
func (a *AvgRateCounter) WithResolution(resolution int) *AvgRateCounter {
	if resolution < 1 {
		panic("AvgRateCounter resolution cannot be less than 1")
	}

	a.hits = a.hits.WithResolution(resolution)
	a.counter = a.counter.WithResolution(resolution)

	return a
}

// Incr Adds an event into the AvgRateCounter
func (a *AvgRateCounter) Incr(val int64) {
	a.hits.Incr(1)
	a.counter.Incr(val)
}

// Rate Returns the current ratio between the events count and its values during the last interval
func (a *AvgRateCounter) Rate() float64 {
	hits, value := a.hits.Rate(), a.counter.Rate()

	if hits == 0 {
		return 0 // Avoid division by zero
	}

	return float64(value) / float64(hits)
}

// Hits returns the number of calling method Incr during specified interval
func (a *AvgRateCounter) Hits() int64 {
	return a.hits.Rate()
}

// String returns counter's rate formatted to string
func (a *AvgRateCounter) String() string {
	return strconv.FormatFloat(a.Rate(), 'e', 5, 64)
}
