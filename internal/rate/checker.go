package rate

import (
	"time"
)

type Checker interface {
	Check() (Stats, bool, error)
}

// SW-REQ-013
type Stats struct {
	Reset     time.Duration
	Limit     int
	Remaining int
	Count     int
}

// SW-REQ-013
func NewEmptyStats() Stats {
	return Stats{
		Reset:     time.Duration(0),
		Limit:     0,
		Remaining: 0,
	}
}

// SW-REQ-013
func (s Stats) ShouldBlock() bool {
	return s.Count > s.Limit
}

// SW-REQ-013
type AnonChecker func() (Stats, bool, error)

// SW-REQ-013
func (ac AnonChecker) Check() (Stats, bool, error) {
	return ac()
}
