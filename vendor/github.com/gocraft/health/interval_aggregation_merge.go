package health

// Merge merges intAgg into ia, mutating ia.
// Requires that ia and intAgg are a fully valid with no nil maps.
func (ia *IntervalAggregation) Merge(intAgg *IntervalAggregation) {
	ia.aggregationMaps.merge(&intAgg.aggregationMaps)

	for k, v := range intAgg.Jobs {
		if existingJob, ok := ia.Jobs[k]; ok {
			existingJob.merge(v)
		} else {
			ia.Jobs[k] = v.Clone()
		}
	}

	ia.SerialNumber++
}

func (intoJob *JobAggregation) merge(fromJob *JobAggregation) {
	intoJob.aggregationMaps.merge(&fromJob.aggregationMaps)
	intoJob.TimerAggregation.merge(&fromJob.TimerAggregation)
	intoJob.CountSuccess += fromJob.CountSuccess
	intoJob.CountValidationError += fromJob.CountValidationError
	intoJob.CountPanic += fromJob.CountPanic
	intoJob.CountError += fromJob.CountError
	intoJob.CountJunk += fromJob.CountJunk
}

func (intoTa *TimerAggregation) merge(fromTa *TimerAggregation) {
	intoTa.Count += fromTa.Count
	intoTa.NanosSum += fromTa.NanosSum
	intoTa.NanosSumSquares += fromTa.NanosSumSquares
	if fromTa.NanosMin < intoTa.NanosMin {
		intoTa.NanosMin = fromTa.NanosMin
	}
	if fromTa.NanosMax > intoTa.NanosMax {
		intoTa.NanosMax = fromTa.NanosMax
	}
}

func (intoAm *aggregationMaps) merge(fromAm *aggregationMaps) {
	for k, v := range fromAm.Events {
		intoAm.Events[k] += v
	}

	for k, v := range fromAm.Gauges {
		intoAm.Gauges[k] = v
	}

	for k, v := range fromAm.Timers {
		if existingTimer, ok := intoAm.Timers[k]; ok {
			existingTimer.merge(v)
		} else {
			intoAm.Timers[k] = v.Clone()
		}
	}

	for k, v := range fromAm.EventErrs {
		if existingErrCounter, ok := intoAm.EventErrs[k]; ok {
			existingErrCounter.Count += v.Count

			// merging two ring buffers given our shitty implementation is problematic.
			for _, err := range v.errorSamples {
				if err != nil {
					existingErrCounter.addError(err)
				}
			}
		} else {
			intoAm.EventErrs[k] = v.Clone()
		}
	}
}
