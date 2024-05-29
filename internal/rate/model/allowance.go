package model

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Allowance is a redis data model type. It's encoded into a redis Hash type.
type Allowance struct {
	// Delay is the minimum time between rate limit changes (in seconds).
	Delay int64 `redis:"delay"`

	// Current holds the current rate limit allowance in effect.
	Current int64 `redis:"current"`

	// NextUpdateAt is the next allowable update time for the allowance.
	NextUpdateAt time.Time `redis:"nextUpdateAt"`
}

// NewAllowance creates a new allowance with the update delay (in seconds).
func NewAllowance(delay int64) *Allowance {
	return &Allowance{
		Delay: delay,
	}
}

// NewAllowanceFromMap will scan the `in` parameter and convert it to *Allowance.
func NewAllowanceFromMap(in map[string]string) *Allowance {
	result := &Allowance{}

	// This block of code ignores errors in favor of the zero value.
	// Regardless of error, the zero value is returned and used.
	result.Delay, _ = strconv.ParseInt(in["delay"], 10, 0)
	result.Current, _ = strconv.ParseInt(in["current"], 10, 0)
	result.NextUpdateAt, _ = time.Parse(time.RFC3339Nano, in["nextUpdateAt"])

	return result
}

// Valid returns false if validation with Err() fails.
func (a *Allowance) Valid() bool {
	err := a.Err()
	return err == nil
}

// Err returns a validation error for *Allowance.
func (a *Allowance) Err() error {
	if a.Delay <= 0 {
		return errors.New("allowance: invalid delay")
	}
	return nil
}

// Map will return an allowance as a map.
func (a *Allowance) Map() map[string]any {
	return map[string]any{
		"delay":        fmt.Sprint(a.Delay),
		"current":      fmt.Sprint(a.Current),
		"nextUpdateAt": a.NextUpdateAt.Format(time.RFC3339Nano),
	}
}

// Reset will clear the allowance.
func (a *Allowance) Reset() {
	if a == nil {
		return
	}
	a.Current = 0
	a.NextUpdateAt = time.Time{}
}

// GetDelay returns the delay for rate limit smoothing as a time.Duration.
func (a *Allowance) GetDelay() time.Duration {
	return time.Second * time.Duration(a.Delay)
}

// Get returns the current allowance.
func (a *Allowance) Get() int64 {
	return a.Current
}

// Set updates the current allowance to the specified value and
// sets the next update time based on the configured delay.
func (a *Allowance) Set(allowance int64) {
	a.Current = allowance
	a.Touch()
}

// Touch updates the next allowance time to the configured delay.
func (a *Allowance) Touch() {
	a.NextUpdateAt = time.Now().Add(a.GetDelay())
}

// Expired checks if the allowance can be updated based on the configured delay.
func (a *Allowance) Expired() bool {
	return time.Since(a.NextUpdateAt) > 0
}
