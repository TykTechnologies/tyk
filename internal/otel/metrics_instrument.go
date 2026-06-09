package otel

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"

	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// reloadDurationBuckets defines histogram bucket boundaries (in seconds) for
// configuration reload durations. Reloads typically range from sub-second to
// tens of seconds under heavy load.
var reloadDurationBuckets = []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0}

// MetricInstruments encapsulates the OTel metrics provider and all gateway instruments.
// All methods are safe to call even when the provider is disabled (noop).
type MetricInstruments struct {
	provider       tykmetric.Provider
	requestCounter *tykmetric.Counter
	registry       *apimetrics.InstrumentRegistry

	// Configuration state gauges.
	apisLoaded     *tykmetric.Gauge
	policiesLoaded *tykmetric.Gauge

	// Reload event metrics.
	reloadCounter  *tykmetric.Counter
	reloadDuration *tykmetric.Histogram
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

	apisLoaded, err := provider.NewGauge(
		"tyk.gateway.apis.loaded",
		"Number of API definitions currently loaded on the gateway",
		"{api}",
	)
	if err != nil {
		logger.Errorf("Creating apis loaded gauge: %s", err)
	}

	policiesLoaded, err := provider.NewGauge(
		"tyk.gateway.policies.loaded",
		"Number of policies currently loaded on the gateway",
		"{policy}",
	)
	if err != nil {
		logger.Errorf("Creating policies loaded gauge: %s", err)
	}

	reloadCounter, err := provider.NewCounter(
		"tyk.gateway.config.reload",
		"Total number of gateway configuration reload cycles",
		"{reload}",
	)
	if err != nil {
		logger.Errorf("Creating reload counter: %s", err)
	}

	reloadDuration, err := provider.NewHistogram(
		"tyk.gateway.config.reload.duration",
		"Duration of gateway configuration reload cycles",
		"s",
		reloadDurationBuckets,
	)
	if err != nil {
		logger.Errorf("Creating reload duration histogram: %s", err)
	}

	return &MetricInstruments{
		provider:       provider,
		requestCounter: requestCounter,
		apisLoaded:     apisLoaded,
		policiesLoaded: policiesLoaded,
		reloadCounter:  reloadCounter,
		reloadDuration: reloadDuration,
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

// SetRegistry creates and attaches an API metric registry from the given
// definitions. This is intended for tests that need to exercise custom
// API metric dimensions without going through the full gateway config flow.
func (i *MetricInstruments) SetRegistry(provider tykmetric.Provider, defs []apimetrics.APIMetricDefinition) {
	registry, err := apimetrics.NewInstrumentRegistry(provider, defs)
	if err != nil {
		panic("SetRegistry: " + err.Error())
	}
	i.registry = registry
}

// NeedsResponse returns true if any API metric instrument uses response_header dimensions.
func (i *MetricInstruments) NeedsResponse() bool {
	return i.registry != nil && i.registry.NeedsResponse()
}

// NeedsMCP returns true if any API metric instrument uses MCP metadata dimensions.
func (i *MetricInstruments) NeedsMCP() bool {
	return i.registry != nil && i.registry.NeedsMCP()
}

// NeedsConfigData returns true if any API metric instrument uses config_data dimensions.
func (i *MetricInstruments) NeedsConfigData() bool {
	return i.registry != nil && i.registry.NeedsConfigData()
}

// RecordConfigState records the current count of loaded APIs and policies.
func (i *MetricInstruments) RecordConfigState(ctx context.Context, apiCount, policyCount int) {
	i.apisLoaded.Record(ctx, float64(apiCount))
	i.policiesLoaded.Record(ctx, float64(policyCount))
}

// RecordReload records a reload event: increments the reload counter and
// records the reload duration in the histogram.
func (i *MetricInstruments) RecordReload(ctx context.Context, duration time.Duration) {
	i.reloadCounter.Add(ctx, 1)
	i.reloadDuration.Record(ctx, duration.Seconds())
}

// Shutdown flushes pending metrics and shuts down the provider.
func (i *MetricInstruments) Shutdown(ctx context.Context) error {
	if err := i.provider.ForceFlush(ctx); err != nil {
		return err
	}
	return i.provider.Shutdown(ctx)
}
