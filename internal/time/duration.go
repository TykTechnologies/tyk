package time

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

type Duration = time.Duration

const (
	Nanosecond  = time.Nanosecond
	Microsecond = time.Microsecond
	Millisecond = time.Millisecond
	Second      = time.Second
	Minute      = time.Minute
	Hour        = time.Hour
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

func (d ReadableDuration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}

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
	duration, _ := time.ParseDuration(in)
	*d = ReadableDuration(duration)
	return nil
}

func (d ReadableDuration) Seconds() float64 {
	return Duration(d).Seconds()
}
