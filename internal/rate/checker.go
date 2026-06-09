package rate

import (
	"time"
)

type Checker interface {
	Check() (Stats, bool, error)
}

type Stats struct {
	Reset     time.Duration
	Limit     int
	Remaining int
	Count     int
}

func NewEmptyStats() Stats {
	return Stats{
		Reset:     time.Duration(0),
		Limit:     0,
		Remaining: 0,
	}
}

func (s Stats) ShouldBlock() bool {
	return s.Count > s.Limit
}

type AnonChecker func() (Stats, bool, error)

func (ac AnonChecker) Check() (Stats, bool, error) {
	return ac()
}
