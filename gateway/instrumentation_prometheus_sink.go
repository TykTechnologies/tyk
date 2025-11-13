package gateway

import (
	"github.com/gocraft/health"
)

// PrometheusSink implements health.Sink interface for Prometheus
type PrometheusSink struct {
	metrics *PrometheusMetrics
}

// NewPrometheusSink creates a new Prometheus sink
func NewPrometheusSink(metrics *PrometheusMetrics) *PrometheusSink {
	return &PrometheusSink{
		metrics: metrics,
	}
}

// EmitEvent converts events to Prometheus metrics
func (s *PrometheusSink) EmitEvent(job, event string, kvs map[string]string) {
	// Events are tracked through specific metric collectors
	// Can be extended if specific event tracking is needed
}

// EmitEventErr tracks errors in Prometheus
func (s *PrometheusSink) EmitEventErr(job, event string, err error, kvs map[string]string) {
	// Error tracking is handled by RecordRequest for HTTP errors
	// Can be extended for non-HTTP errors if needed
}

// EmitTiming converts timing events to histograms
func (s *PrometheusSink) EmitTiming(job, event string, nanos int64, kvs map[string]string) {
	seconds := float64(nanos) / 1e9

	// Track middleware execution timing
	if job == "MiddlewareCall" {
		if mwName, ok := kvs["mw_name"]; ok {
			apiID := kvs["api_id"]
			s.metrics.RecordMiddlewareExecution(mwName, apiID, seconds)
		}
	}

	// Can be extended for other timing events
}

// EmitGauge handles gauge metrics
func (s *PrometheusSink) EmitGauge(job, event string, value float64, kvs map[string]string) {
	// Gauge metrics are updated periodically by UpdateSystemMetrics/UpdateGatewayMetrics
	// Can be extended if specific gauge tracking is needed beyond the existing collectors
}

// EmitComplete tracks completion status
func (s *PrometheusSink) EmitComplete(job string, status health.CompletionStatus, nanos int64, kvs map[string]string) {
	// Completion status is tracked through RecordRequest
	// Can be extended if additional completion tracking is needed
}
