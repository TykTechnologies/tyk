package time

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
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

const (
	EndingHour        = "h"
	EndingMinute      = "m"
	EndingSecond      = "s"
	EndingMillisecond = "ms"
	EndingMicrosecond = "µs"
	EndingNanosecond  = "ns"
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
	return []byte(fmt.Sprintf(`"%s"`, d.format())), nil
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

// Seconds returns ReadableDuration rounded down to the seconds.
func (d ReadableDuration) Seconds() float64 {
	durationInSeconds := math.Floor(Duration(d).Seconds())
	return durationInSeconds
}

// Millisecond returns ReadableDuration in milliseconds.
func (d ReadableDuration) Milliseconds() int64 {
	return Duration(d).Milliseconds()
}

// Nanoseconds returns ReadableDuration in nanoseconds.
func (d ReadableDuration) Nanoseconds() int64 {
	return Duration(d).Nanoseconds()
}

// Microseconds returns ReadableDuration in microseconds.
func (d ReadableDuration) Microseconds() int64 {
	return Duration(d).Microseconds()
}

// formats time duration dur to validation pattern ^(\d+h)?(\d+m)?(\d+s)?(\d+ms)?(\d+µs)?(\d+ns)%
func (d ReadableDuration) format() string {
	if d == 0 {
		return "0s"
	}

	var sb strings.Builder
	var rest = int64(d)

	if rest < 0 {
		rest *= -1
		sb.WriteByte('-')
	}

	for _, conv := range convertCases {
		if rest == 0 {
			break
		}

		curr := rest / int64(conv.duration)
		rest -= curr * int64(conv.duration)

		if curr == 0 {
			continue
		}

		sb.WriteString(strconv.FormatInt(curr, 10))
		sb.WriteString(conv.ending)
	}

	return sb.String()
}

type convertCase struct {
	duration time.Duration
	ending   string
}

var convertCases = []convertCase{
	{time.Hour, EndingHour},
	{time.Minute, EndingMinute},
	{time.Second, EndingSecond},
	{time.Millisecond, EndingMillisecond},
	{time.Microsecond, EndingMicrosecond},
	{time.Nanosecond, EndingNanosecond},
}
