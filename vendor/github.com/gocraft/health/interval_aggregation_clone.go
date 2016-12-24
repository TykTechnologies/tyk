package health

// Clone does a deep clone of ia, duplicating all maps and whatnot.
func (ia *IntervalAggregation) Clone() *IntervalAggregation {
	dup := &IntervalAggregation{}
	dup.IntervalStart = ia.IntervalStart
	dup.SerialNumber = ia.SerialNumber
	dup.aggregationMaps = *ia.aggregationMaps.Clone()

	dup.Jobs = make(map[string]*JobAggregation)
	for k, v := range ia.Jobs {
		dup.Jobs[k] = v.Clone()
	}

	return dup
}

func (am *aggregationMaps) Clone() *aggregationMaps {
	dup := &aggregationMaps{}

	dup.initAggregationMaps()

	for k, v := range am.Events {
		dup.Events[k] = v
	}

	for k, v := range am.Gauges {
		dup.Gauges[k] = v
	}

	for k, v := range am.Timers {
		dup.Timers[k] = v.Clone()
	}

	for k, v := range am.EventErrs {
		dup.EventErrs[k] = v.Clone()
	}

	return dup
}

func (ta *TimerAggregation) Clone() *TimerAggregation {
	var dup = *ta
	return &dup
}

func (ec *ErrorCounter) Clone() *ErrorCounter {
	var dup = *ec
	return &dup
}

func (ja *JobAggregation) Clone() *JobAggregation {
	dup := &JobAggregation{
		CountSuccess:         ja.CountSuccess,
		CountValidationError: ja.CountValidationError,
		CountPanic:           ja.CountPanic,
		CountError:           ja.CountError,
		CountJunk:            ja.CountJunk,
	}

	dup.aggregationMaps = *ja.aggregationMaps.Clone()
	dup.TimerAggregation = ja.TimerAggregation

	return dup
}
