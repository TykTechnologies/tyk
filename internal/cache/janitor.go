package cache

import (
	"time"
)

// Janitor is responsible for performing periodic cleanup operations.
type Janitor struct {
	Interval time.Duration
	stop     chan bool
}

// NewJanitor returns a new Janitor that performs cleanup at the specified interval.
func NewJanitor(interval time.Duration, cleanup func()) *Janitor {
	janitor := &Janitor{
		Interval: interval,
		stop:     make(chan bool, 1),
	}

	go janitor.Run(cleanup)

	return janitor
}

// Run starts the janitor which calls the provided cleanup function at every interval.
func (j *Janitor) Run(cleanup func()) {
	ticker := time.NewTicker(j.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanup()
		case <-j.stop:
			close(j.stop)
			return
		}
	}
}

// Close stops the janitor from performing further cleanup operations.
func (j *Janitor) Close() {
	j.stop <- true
}
