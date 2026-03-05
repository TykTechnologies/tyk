package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"

	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// MetricInstruments encapsulates the OTel metrics provider and all gateway instruments.
// All methods are safe to call even when the provider is disabled (noop).
type MetricInstruments struct {
	provider       tykmetric.Provider
	requestCounter *tykmetric.Counter
	registry       *apimetrics.InstrumentRegistry
}

// NewMetricInstruments creates gateway metric instruments from an existing provider.
func NewMetricInstruments(provider tykmetric.Provider, logger *logrus.Logger) *MetricInstruments {
	requestCounter, err := provider.NewCounter(
		"tyk.http.requests",
		"Total HTTP requests processed by the gateway",
		"1",
	)
	if err != nil {
		logger.Errorf("Creating request counter: %s", err)
	}

	return &MetricInstruments{
		provider:       provider,
		requestCounter: requestCounter,
	}
}

// RecordRequest increments the request counter.
func (i *MetricInstruments) RecordRequest(ctx context.Context) {
	i.requestCounter.Add(ctx, 1)
}

// RecordAPIMetrics records all configured API-level metrics for a request.
func (i *MetricInstruments) RecordAPIMetrics(ctx context.Context, rc *apimetrics.RequestContext) {
	if i.registry != nil {
		i.registry.RecordAPIMetrics(ctx, rc)
	}
}

// NeedsSession returns true if any API metric instrument uses session dimensions.
func (i *MetricInstruments) NeedsSession() bool {
	return i.registry != nil && i.registry.NeedsSession()
}

// NeedsContext returns true if any API metric instrument uses context dimensions.
func (i *MetricInstruments) NeedsContext() bool {
	return i.registry != nil && i.registry.NeedsContext()
}

// NeedsResponse returns true if any API metric instrument uses response_header dimensions.
func (i *MetricInstruments) NeedsResponse() bool {
	return i.registry != nil && i.registry.NeedsResponse()
}

// Shutdown flushes pending metrics and shuts down the provider.
func (i *MetricInstruments) Shutdown(ctx context.Context) error {
	if err := i.provider.ForceFlush(ctx); err != nil {
		return err
	}
	return i.provider.Shutdown(ctx)
}
