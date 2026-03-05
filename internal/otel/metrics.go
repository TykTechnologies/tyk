package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"

	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// NewMetricProvider creates an OTel metrics provider with the given metrics configuration.
func NewMetricProvider(ctx context.Context, logger *logrus.Logger, metricsCfg *BaseMetricsConfig,
	id string, version string) (tykmetric.Provider, error) {

	metricLogger := logger.WithFields(logrus.Fields{
		"component": "otel-metrics",
	})

	return tykmetric.NewProvider(
		tykmetric.WithContext(ctx),
		tykmetric.WithConfig(metricsCfg),
		tykmetric.WithLogger(metricLogger),
		tykmetric.WithServiceID(id),
		tykmetric.WithServiceVersion(version),
		tykmetric.WithHostDetector(),
		tykmetric.WithContainerDetector(),
		tykmetric.WithProcessDetector(),
	)
}

// InitOpenTelemetryMetrics creates a metrics provider and instruments in one call.
// APIMetrics config is read from gwConfig.Metrics.APIMetrics using slice semantics:
//
//	nil (field omitted)  → default RED instruments created
//	empty slice          → no API metrics (explicitly disabled)
//	populated slice      → only configured instruments
func InitOpenTelemetryMetrics(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry,
	id string, version string) *MetricInstruments {

	provider, err := NewMetricProvider(ctx, logger, &gwConfig.Metrics.BaseMetricsConfig, id, version)
	if err != nil {
		logger.Errorf("Initializing OpenTelemetry Metrics: %s", err)
		return &MetricInstruments{}
	}

	// Resolve API metrics definitions using slice semantics.
	var defs []apimetrics.APIMetricDefinition
	switch {
	case gwConfig.Metrics.APIMetrics == nil:
		defs = apimetrics.DefaultAPIMetrics()
	case len(gwConfig.Metrics.APIMetrics) == 0:
		defs = nil
	default:
		defs = []apimetrics.APIMetricDefinition(gwConfig.Metrics.APIMetrics)
	}

	inst := NewMetricInstruments(provider, logger)

	if defs != nil {
		registry, err := apimetrics.NewInstrumentRegistry(provider, defs)
		if err != nil {
			logger.WithError(err).Error("failed to create API metric instruments, falling back to no API metrics")
		} else {
			inst.registry = registry
		}
	}

	return inst
}
