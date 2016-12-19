/*
Package ratecounter provides a thread-safe rate-counter, for tracking counts
in an interval

Useful for implementing counters and stats of 'requests-per-second' (for example).

  // We're recording marks-per-1second
  counter := ratecounter.NewRateCounter(1 * time.Second)

  // Record an event happening
  counter.Mark()

  // get the current requests-per-second
  counter.Rate()

To record an average over a longer period, you can:

  // Record requests-per-minute
  counter := ratecounter.NewRateCounter(60 * time.Second)

  // Calculate the average requests-per-second for the last minute
  counter.Rate() / 60
*/
package ratecounter
