package otel

import (
	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"

	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// general type aliases
type (
	TracerProvider = tyktrace.Provider

	// BaseOpenTelemetry is the library's OpenTelemetry configuration type.
	// Used as the embedded field in OpenTelemetry.
	BaseOpenTelemetry = otelconfig.OpenTelemetry

	ExporterConfig = otelconfig.ExporterConfig

	Sampling = otelconfig.Sampling

	BaseMetricsConfig = otelconfig.MetricsConfig

	MetricsRetryConfig = otelconfig.MetricsRetryConfig

	SpanBatchConfig = otelconfig.SpanBatchConfig

	SpanAttribute = tyktrace.Attribute

	Span = tyktrace.Span
)

// MetricsConfig wraps the library's MetricsConfig and adds gateway-specific
// fields. This keeps api_metrics nested under opentelemetry.metrics in JSON:
//
//	{"opentelemetry": {"metrics": {"enabled": true, "api_metrics": [...]}}}
type MetricsConfig struct {
	BaseMetricsConfig `json:",inline"`

	// RuntimeMetrics enables Go runtime metrics collection (goroutines, memory, GC).
	// Defaults to true when metrics are enabled.
	RuntimeMetrics *bool `json:"runtime_metrics"`

	// APIMetrics defines the metric instruments created at startup.
	// Each instrument has its own dimension scope — only declared dimensions are recorded.
	//
	// Slice semantics:
	//   nil (field omitted)  → default RED instruments created
	//   empty slice          → no API metrics (explicitly disabled)
	//   populated slice      → only configured instruments
	APIMetrics apimetrics.APIMetricDefinitions `json:"api_metrics"`
}

// TracesConfig wraps the library's trace config for nesting under
// "opentelemetry.traces". When present, trace settings are read from
// this sub-object instead of the root-level inline fields.
type TracesConfig struct {
	BaseOpenTelemetry `json:",inline"`
}

// OpenTelemetry wraps the library trace config and adds Traces and Metrics sections.
// The library's OpenTelemetry no longer contains Metrics, so the gateway
// owns the association via this wrapper. Both trace and metrics configs
// embed ExporterConfig independently, allowing separate collector targets.
//
// Root-level trace fields (via BaseOpenTelemetry inline) are preserved for
// backward compatibility. When Traces is non-nil, it takes precedence.
type OpenTelemetry struct {
	// Deprecated: root-level trace fields preserved for backward compatibility.
	// Use opentelemetry.traces for new configurations.
	BaseOpenTelemetry `json:",inline"`

	// Traces holds the OpenTelemetry traces configuration.
	// When non-nil, takes precedence over root-level trace fields.
	Traces *TracesConfig `json:"traces,omitempty"`

	// Metrics holds the OpenTelemetry metrics configuration.
	Metrics MetricsConfig `json:"metrics"`
}

// TracesEnabled reports whether tracing is enabled. It checks the Traces
// sub-object first (new format); if absent or zero-valued, falls back to
// the root-level Enabled field (legacy format).
//
// The zero-value check handles envconfig, which allocates pointer fields
// during processing even when no corresponding env vars are set.
//
// Value receiver so it can be called on non-addressable values (e.g.
// GetConfig().OpenTelemetry.TracesEnabled()).
func (c OpenTelemetry) TracesEnabled() bool {
	if c.Traces != nil && c.Traces.Enabled {
		return true
	}
	return c.Enabled
}

// EffectiveTraceConfig returns the trace configuration that should be used.
// If Traces is non-nil and enabled (new format), it returns
// &Traces.BaseOpenTelemetry; otherwise it returns the root-level
// &c.BaseOpenTelemetry (legacy format).
func (c *OpenTelemetry) EffectiveTraceConfig() *BaseOpenTelemetry {
	if c.Traces != nil && c.Traces.Enabled {
		return &c.Traces.BaseOpenTelemetry
	}
	return &c.BaseOpenTelemetry
}

// effectiveTraceExporterConfig returns the ExporterConfig from the effective
// trace source (Traces sub-object or root-level).
func (c *OpenTelemetry) effectiveTraceExporterConfig() ExporterConfig {
	return c.EffectiveTraceConfig().ExporterConfig
}

// inheritExporterConfig copies zero-valued exporter fields in dst from src.
func inheritExporterConfig(dst *ExporterConfig, src ExporterConfig) {
	if dst.Exporter == "" {
		dst.Exporter = src.Exporter
	}
	if dst.Endpoint == "" {
		dst.Endpoint = src.Endpoint
	}
	if dst.Headers == nil {
		dst.Headers = src.Headers
	}
	if dst.ConnectionTimeout == 0 {
		dst.ConnectionTimeout = src.ConnectionTimeout
	}
	if dst.ResourceName == "" {
		dst.ResourceName = src.ResourceName
	}
	if (dst.TLS == otelconfig.TLS{}) {
		dst.TLS = src.TLS
	}
}

// SetDefaults shadows BaseOpenTelemetry.SetDefaults to also handle metrics
// exporter inheritance. Trace defaults are applied first, then zero-valued
// metrics exporter fields are filled from the effective trace config, then
// metrics-specific defaults fill any remaining gaps.
func (c *OpenTelemetry) SetDefaults() {
	// 1. Apply trace defaults to the effective trace config.
	c.EffectiveTraceConfig().SetDefaults()

	// 2. Inherit trace exporter → metrics exporter for zero-valued fields.
	inheritExporterConfig(&c.Metrics.ExporterConfig, c.effectiveTraceExporterConfig())

	// 3. Fill remaining gaps with library defaults (export interval, temporality, etc.).
	c.Metrics.SetDefaults()
}

// LibraryConfig returns the effective trace config for passing to
// trace library functions that expect *otelconfig.OpenTelemetry.
func (c *OpenTelemetry) LibraryConfig() *otelconfig.OpenTelemetry {
	return c.EffectiveTraceConfig()
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
