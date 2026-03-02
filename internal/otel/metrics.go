package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// NewMetricProvider creates an OTel metrics provider with the given metrics configuration.
func NewMetricProvider(ctx context.Context, logger *logrus.Logger, metricsCfg *MetricsConfig,
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
func InitOpenTelemetryMetrics(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry,
	id string, version string) *MetricInstruments {

	provider, err := NewMetricProvider(ctx, logger, &gwConfig.Metrics, id, version)
	if err != nil {
		logger.Errorf("Initializing OpenTelemetry Metrics: %s", err)
	}

	return NewMetricInstruments(provider, logger)
}
