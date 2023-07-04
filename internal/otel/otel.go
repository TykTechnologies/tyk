package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/TykTechnologies/tyk/config"
)

type TracerProvider = tyktrace.Provider

// InitOpenTelemetry initializes OpenTelemetry - it returns a TracerProvider
// which can be used to create a tracer. If OpenTelemetry is disabled or misconfigured,
// a NoopProvider is returned.
func InitOpenTelemetry(ctx context.Context, logger *logrus.Logger, gwConfig *config.Config) TracerProvider {

	traceLogger := logger.WithFields(logrus.Fields{
		"exporter":           gwConfig.OpenTelemetry.Exporter,
		"endpoint":           gwConfig.OpenTelemetry.Endpoint,
		"connection_timeout": gwConfig.OpenTelemetry.ConnectionTimeout,
	})

	provider, errOtel := tyktrace.NewProvider(
		tyktrace.WithContext(ctx),
		tyktrace.WithConfig(&gwConfig.OpenTelemetry),
		tyktrace.WithLogger(traceLogger),
	)

	if errOtel != nil {
		logger.Errorf("Initializing OpenTelemetry %s", errOtel)
	}

	return provider
}
