# ratecounter

[![CircleCI](https://circleci.com/gh/paulbellamy/ratecounter.svg?style=svg)](https://circleci.com/gh/paulbellamy/ratecounter)
[![Go Report Card](https://goreportcard.com/badge/github.com/paulbellamy/ratecounter)](https://goreportcard.com/report/github.com/paulbellamy/ratecounter)
[![GoDoc](https://godoc.org/github.com/paulbellamy/ratecounter?status.svg)](https://godoc.org/github.com/paulbellamy/ratecounter)
[![codecov](https://codecov.io/gh/paulbellamy/ratecounter/branch/master/graph/badge.svg)](https://codecov.io/gh/paulbellamy/ratecounter)

A Thread-Safe RateCounter implementation in Golang

## Usage

```
import "github.com/paulbellamy/ratecounter"
```

Package ratecounter provides a thread-safe rate-counter, for tracking
counts in an interval

Useful for implementing counters and stats of 'requests-per-second' (for
example):

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

Also you can track average value of some metric in an interval.

Useful for implementing counters and stats of 'average-execution-time' (for
example):

```go
// We're recording average execution time of some heavy operation in the last minute.
counter := ratecounter.NewAvgRateCounter(60 * time.Second)
// Start timer.
startTime := time.Now()
// Execute heavy operation.
heavyOperation()
// Record elapsed time.
counter.Incr(time.Since(startTime).Nanoseconds())
// Get the current average execution time.
counter.Rate()
```

## Documentation

Check latest documentation on [go doc](https://godoc.org/github.com/paulbellamy/ratecounter).

