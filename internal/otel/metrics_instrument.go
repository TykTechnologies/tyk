package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// MetricInstruments encapsulates the OTel metrics provider and all gateway instruments.
// All methods are safe to call even when the provider is disabled (noop).
type MetricInstruments struct {
	provider       tykmetric.Provider
	requestCounter *tykmetric.Counter
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

// Shutdown flushes pending metrics and shuts down the provider.
func (i *MetricInstruments) Shutdown(ctx context.Context) error {
	if err := i.provider.ForceFlush(ctx); err != nil {
		return err
	}
	return i.provider.Shutdown(ctx)
}
