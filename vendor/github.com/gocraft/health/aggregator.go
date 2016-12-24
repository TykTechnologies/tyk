package health

import (
	"time"
)

type aggregator struct {
	// How long is each aggregation interval. Eg, 1 minute
	intervalDuration time.Duration

	// Retain controls how many metrics interval we keep. Eg, 5 minutes
	retain time.Duration

	// maxIntervals is the maximum length of intervals.
	// It is retain / interval.
	maxIntervals int

	// intervals is a slice of the retained intervals
	intervalAggregations []*IntervalAggregation
}

func startAggregator(intervalDuration time.Duration, retain time.Duration, sink *JsonPollingSink) {
	cmdChan := sink.cmdChan
	doneChan := sink.doneChan
	intervalsChanChan := sink.intervalsChanChan
	ticker := time.Tick(1 * time.Second)

	agg := newAggregator(intervalDuration, retain)

AGGREGATE_LOOP:
	for {
		select {
		case <-doneChan:
			sink.doneDoneChan <- 1
			break AGGREGATE_LOOP
		case cmd := <-cmdChan:
			if cmd.Kind == cmdKindEvent {
				agg.EmitEvent(cmd.Job, cmd.Event)
			} else if cmd.Kind == cmdKindEventErr {
				agg.EmitEventErr(cmd.Job, cmd.Event, cmd.Err)
			} else if cmd.Kind == cmdKindTiming {
				agg.EmitTiming(cmd.Job, cmd.Event, cmd.Nanos)
			} else if cmd.Kind == cmdKindGauge {
				agg.EmitGauge(cmd.Job, cmd.Event, cmd.Value)
			} else if cmd.Kind == cmdKindComplete {
				agg.EmitComplete(cmd.Job, cmd.Status, cmd.Nanos)
			}
		case <-ticker:
			agg.getIntervalAggregation() // this has the side effect of sliding the interval window if necessary.
		case intervalsChan := <-intervalsChanChan:
			intervalsChan <- agg.memorySafeIntervals()
		}
	}
}

func newAggregator(intervalDuration time.Duration, retain time.Duration) *aggregator {
	maxIntervals := int(retain / intervalDuration)
	return &aggregator{
		intervalDuration:     intervalDuration,
		retain:               retain,
		maxIntervals:         maxIntervals,
		intervalAggregations: make([]*IntervalAggregation, 0, maxIntervals),
	}
}

func (a *aggregator) memorySafeIntervals() []*IntervalAggregation {
	ret := make([]*IntervalAggregation, 0, len(a.intervalAggregations))
	curAgg := a.getIntervalAggregation()

	for _, intAgg := range a.intervalAggregations {
		if intAgg == curAgg {
			ret = append(ret, intAgg.Clone())
		} else {
			ret = append(ret, intAgg)
		}
	}

	return ret
}

func (a *aggregator) EmitEvent(job string, event string) {
	intAgg := a.getIntervalAggregation()
	intAgg.Events[event] = intAgg.Events[event] + 1
	jobAgg := intAgg.getJobAggregation(job)
	jobAgg.Events[event] = jobAgg.Events[event] + 1
	intAgg.SerialNumber++
}

func (a *aggregator) EmitEventErr(job string, event string, inputErr error) {
	intAgg := a.getIntervalAggregation()
	errc := intAgg.getCounterErrs(event)
	errc.incrementAndAddError(inputErr)
	jobAgg := intAgg.getJobAggregation(job)
	jerrc := jobAgg.getCounterErrs(event)
	jerrc.incrementAndAddError(inputErr)
	intAgg.SerialNumber++
}

func (a *aggregator) EmitTiming(job string, event string, nanos int64) {
	intAgg := a.getIntervalAggregation()
	t := intAgg.getTimers(event)
	t.ingest(nanos)
	jobAgg := intAgg.getJobAggregation(job)
	jt := jobAgg.getTimers(event)
	jt.ingest(nanos)
	intAgg.SerialNumber++
}

func (a *aggregator) EmitGauge(job string, event string, value float64) {
	intAgg := a.getIntervalAggregation()
	intAgg.Gauges[event] = value
	jobAgg := intAgg.getJobAggregation(job)
	jobAgg.Gauges[event] = value
	intAgg.SerialNumber++
}

func (a *aggregator) EmitComplete(job string, status CompletionStatus, nanos int64) {
	intAgg := a.getIntervalAggregation()
	jobAgg := intAgg.getJobAggregation(job)
	jobAgg.ingest(status, nanos)
	intAgg.SerialNumber++
}

func (a *aggregator) getIntervalAggregation() *IntervalAggregation {
	intervalStart := now().Truncate(a.intervalDuration)

	n := len(a.intervalAggregations)
	if n > 0 && a.intervalAggregations[n-1].IntervalStart == intervalStart {
		return a.intervalAggregations[n-1]
	}

	return a.createIntervalAggregation(intervalStart)
}

func (a *aggregator) createIntervalAggregation(interval time.Time) *IntervalAggregation {
	// Make new interval:
	current := NewIntervalAggregation(interval)

	// If we've reached our max intervals, and we're going to shift everything down, then set the last one
	n := len(a.intervalAggregations)
	if n == a.maxIntervals {
		for i := 1; i < n; i++ {
			a.intervalAggregations[i-1] = a.intervalAggregations[i]
		}
		a.intervalAggregations[n-1] = current
	} else {
		a.intervalAggregations = append(a.intervalAggregations, current)
	}

	return current
}

var nowMock time.Time

func now() time.Time {
	if nowMock.IsZero() {
		return time.Now()
	}
	return nowMock
}

func setNowMock(t string) {
	var err error
	nowMock, err = time.Parse(time.RFC3339, t)
	if err != nil {
		panic(err)
	}
}

func resetNowMock() {
	nowMock = time.Time{}
}
