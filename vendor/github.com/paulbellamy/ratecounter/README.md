# ratecounter

A Thread-Safe RateCounter implementation in Golang

## Usage

```
import "github.com/paulbellamy/ratecounter"
```

Package ratecounter provides a thread-safe rate-counter, for tracking
counts in an interval

Useful for implementing counters and stats of 'requests-per-second' (for
example).

```go
// We're recording marks-per-1second
counter := ratecounter.NewRateCounter(1 * time.Second)
// Record an event happening
counter.Incr(1)
// get the current requests-per-second
counter.Rate()
```

To record an average over a longer period, you can:

```go
// Record requests-per-minute
counter := ratecounter.NewRateCounter(60 * time.Second)
// Calculate the average requests-per-second for the last minute
counter.Rate() / 60
```

## Documentation

```
type Counter struct {
    // contains filtered or unexported fields
}
    A Counter is a thread-safe counter implementation

func NewCounter() *Counter
    NewCounter is used to construct a new Counter object

func (c *Counter) Incr(val int64)
    Increment the counter by some value

func (c *Counter) Value() int64
    Return the counter's current value

type RateCounter struct {
    // contains filtered or unexported fields
}
    A RateCounter is a thread-safe counter which returns the number of times
    'Mark' has been called in the last interval

func NewRateCounter(intrvl time.Duration) *RateCounter
    Constructs a new RateCounter, for the interval provided

func (r *RateCounter) Mark()
    Add 1 event into the RateCounter

func (r *RateCounter) Rate() int64
    Return the current number of events in the last interval
```
