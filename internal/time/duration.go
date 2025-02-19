package time

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Duration is an alias maintained to be used across the project.
type Duration = time.Duration

const (
	// Nanosecond is an alias maintained to be used across the project.
	Nanosecond = time.Nanosecond
	// Microsecond is an alias maintained to be used across the project.
	Microsecond = time.Microsecond
	// Millisecond is an alias maintained to be used across the project.
	Millisecond = time.Millisecond
	// Second is an alias maintained to be used across the project.
	Second = time.Second
	// Minute is an alias maintained to be used across the project.
	Minute = time.Minute
	// Hour is an alias maintained to be used across the project.
	Hour = time.Hour
)

// ReadableDuration is a type alias for time.Duration, so that shorthand notation can be used.
// Examples of valid shorthand notations:
// - "1h"   : one hour
// - "20m"  : twenty minutes
// - "30s"  : thirty seconds
// - "1m29s": one minute and twenty-nine seconds
// - "1h30m" : one hour and thirty minutes
//
// An empty value is interpreted as "0s".
// It's important to format the string correctly, as invalid formats will
// be considered as 0s/empty.
type ReadableDuration time.Duration

// MarshalJSON converts ReadableDuration into human-readable shorthand notation for time.Duration into json format.
func (d ReadableDuration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}

// UnmarshalJSON converts human-readable shorthand notation for time.Duration into ReadableDuration from json format.
func (d *ReadableDuration) UnmarshalJSON(data []byte) error {
	in, err := strconv.Unquote(string(data))
	if err != nil {
		return errors.New("error while parsing duration")
	}

	if in == "" {
		*d = 0
		return nil
	}

	// suppress error, return zero value
	duration, _ := time.ParseDuration(in) //nolint:errcheck
	*d = ReadableDuration(duration)
	return nil
}

// Seconds returns ReadableDuration in seconds.
func (d ReadableDuration) Seconds() float64 {
	return Duration(d).Seconds()
}
