package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// Instruments encapsulates the OTel metrics provider and all gateway instruments.
// All methods are safe to call even when the provider is disabled (noop).
type Instruments struct {
	provider       tykmetric.Provider
	requestCounter *tykmetric.Counter
}

// RecordRequest increments the request counter.
func (i *Instruments) RecordRequest(ctx context.Context) {
	i.requestCounter.Add(ctx, 1)
}

// Shutdown flushes pending metrics and shuts down the provider.
func (i *Instruments) Shutdown(ctx context.Context) error {
	if err := i.provider.ForceFlush(ctx); err != nil {
		return err
	}
	return i.provider.Shutdown(ctx)
}

func InitOpenTelemetryMetrics(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry,
	id string, version string, isDataplane bool, groupID string,
	isSegmented bool, segmentTags []string) *Instruments {

	metricLogger := logger.WithFields(logrus.Fields{
		"component": "otel-metrics",
	})

	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(ctx),
		tykmetric.WithConfig(gwConfig),
		tykmetric.WithLogger(metricLogger),
		tykmetric.WithServiceID(id),
		tykmetric.WithServiceVersion(version),
		tykmetric.WithHostDetector(),
		tykmetric.WithContainerDetector(),
		tykmetric.WithProcessDetector(),
		tykmetric.WithCustomResourceAttributes(GatewayResourceAttributes(
			id, isDataplane, groupID, isSegmented, segmentTags,
		)...),
	)
	if err != nil {
		logger.Errorf("Initializing OpenTelemetry Metrics: %s", err)
	}

	requestCounter, err := provider.NewCounter(
		"tyk.http.requests",
		"Total HTTP requests processed by the gateway",
		"1",
	)
	if err != nil {
		logger.Errorf("Creating request counter: %s", err)
	}

	return &Instruments{
		provider:       provider,
		requestCounter: requestCounter,
	}
}
