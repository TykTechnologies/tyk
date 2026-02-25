package otel

import (
	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
)

// general type aliases
type (
	TracerProvider = tyktrace.Provider

	// BaseOpenTelemetry is the library's OpenTelemetry configuration type.
	// Used as the embedded field in OpenTelemetry.
	BaseOpenTelemetry = otelconfig.OpenTelemetry

	ExporterConfig = otelconfig.ExporterConfig

	Sampling = otelconfig.Sampling

	MetricsConfig = otelconfig.MetricsConfig

	MetricsRetryConfig = otelconfig.MetricsRetryConfig

	SpanAttribute = tyktrace.Attribute

	Span = tyktrace.Span
)

// OpenTelemetry wraps the library trace config and adds a Metrics section.
// The library's OpenTelemetry no longer contains Metrics, so the gateway
// owns the association via this wrapper. Both trace and metrics configs
// embed ExporterConfig independently, allowing separate collector targets.
type OpenTelemetry struct {
	BaseOpenTelemetry `json:",inline"`

	// Metrics holds the OpenTelemetry metrics configuration.
	Metrics MetricsConfig `json:"metrics"`
}

// SetDefaults shadows BaseOpenTelemetry.SetDefaults to also handle metrics
// exporter inheritance. Trace defaults are applied first, then zero-valued
// metrics exporter fields are filled from the trace config, then
// metrics-specific defaults fill any remaining gaps.
func (c *OpenTelemetry) SetDefaults() {
	// 1. Apply trace defaults (exporter, span processor, propagation, sampling).
	c.BaseOpenTelemetry.SetDefaults()

	// 2. Inherit trace ExporterConfig → metrics ExporterConfig for zero-valued fields.
	if c.Metrics.Exporter == "" {
		c.Metrics.Exporter = c.Exporter
	}
	if c.Metrics.Endpoint == "" {
		c.Metrics.Endpoint = c.Endpoint
	}
	if c.Metrics.Headers == nil {
		c.Metrics.Headers = c.Headers
	}
	if c.Metrics.ConnectionTimeout == 0 {
		c.Metrics.ConnectionTimeout = c.ConnectionTimeout
	}
	if c.Metrics.ResourceName == "" {
		c.Metrics.ResourceName = c.ResourceName
	}
	if (c.Metrics.TLS == otelconfig.TLS{}) {
		c.Metrics.TLS = c.TLS
	}

	// 3. Fill remaining gaps with library defaults (export interval, temporality, etc.).
	c.Metrics.SetDefaults()
}

// LibraryConfig returns the underlying library config for passing to
// trace library functions that expect *otelconfig.OpenTelemetry.
func (c *OpenTelemetry) LibraryConfig() *otelconfig.OpenTelemetry {
	return &c.BaseOpenTelemetry
}

// HTTP Handlers
var (
	HTTPHandler = tyktrace.NewHTTPHandler

	HTTPRoundTripper = tyktrace.NewHTTPTransport
)

// span const
const (
	SPAN_STATUS_OK    = tyktrace.SPAN_STATUS_OK
	SPAN_STATUS_ERROR = tyktrace.SPAN_STATUS_ERROR
	SPAN_STATUS_UNSET = tyktrace.SPAN_STATUS_UNSET
)

const (
	NON_VERSIONED = "Non Versioned"
)
