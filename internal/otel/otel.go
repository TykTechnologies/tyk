package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
)

type TracerProvider = tyktrace.Provider

type Config = otelconfig.OpenTelemetry

type Sampling = otelconfig.Sampling

var HTTPHandler = tyktrace.NewHTTPHandler

var HTTPRoundTripper = tyktrace.NewHTTPTransport

const (
	SPAN_STATUS_OK    = tyktrace.SPAN_STATUS_OK
	SPAN_STATUS_ERROR = tyktrace.SPAN_STATUS_ERROR
	SPAN_STATUS_UNSET = tyktrace.SPAN_STATUS_UNSET
)

// InitOpenTelemetry initializes OpenTelemetry - it returns a TracerProvider
// which can be used to create a tracer. If OpenTelemetry is disabled or misconfigured,
// a NoopProvider is returned.
func InitOpenTelemetry(ctx context.Context, logger *logrus.Logger, gwConfig *Config) TracerProvider {

	traceLogger := logger.WithFields(logrus.Fields{
		"exporter":           gwConfig.Exporter,
		"endpoint":           gwConfig.Endpoint,
		"connection_timeout": gwConfig.ConnectionTimeout,
	})

	provider, errOtel := tyktrace.NewProvider(
		tyktrace.WithContext(ctx),
		tyktrace.WithConfig(gwConfig),
		tyktrace.WithLogger(traceLogger),
	)

	if errOtel != nil {
		logger.Errorf("Initializing OpenTelemetry %s", errOtel)
	}

	return provider
}
