package apimetrics

import "context"

// RecordAPIMetrics iterates all instruments, applies filters, builds
// per-instrument attribute sets, and records the value.
func (reg *InstrumentRegistry) RecordAPIMetrics(ctx context.Context, rc *RequestContext) {
	if rc == nil || rc.Request == nil {
		return
	}
	for _, inst := range reg.instruments {
		if !inst.Filter.Match(rc.APIID, rc.Request.Method, rc.StatusCode) {
			continue
		}

		ref, kvs := inst.Builder.Build(rc)

		switch inst.Type {
		case "counter":
			inst.Counter.Add(ctx, 1, kvs...)
		case "histogram":
			var ms int64
			switch inst.HistogramSource {
			case "total":
				ms = rc.LatencyTotal
			case "gateway":
				ms = rc.LatencyGateway
			case "upstream":
				ms = rc.LatencyUpstream
			}
			inst.Histogram.Record(ctx, float64(ms)/1000.0, kvs...)
		}

		inst.Builder.Release(ref)
	}
}
