package otel

import (
	"context"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// Metric type aliases for use in the gateway.
type (
	// MeterProvider is the interface for the OpenTelemetry meter provider.
	MeterProvider = tykmetric.Provider
)

const (
	// Metric names following OpenTelemetry semantic conventions.
	metricRequestTotal    = "http.server.request.total"
	metricRequestErrors   = "http.server.request.errors"
	metricRequestDuration = "http.server.request.duration"
	metricGatewayLatency  = "tyk.gateway.latency"
	metricUpstreamLatency = "tyk.upstream.latency"

	// Unit definitions.
	unitDimensionless = "1"
	unitMilliseconds  = "ms"
)

// MetricLatency holds timing breakdown for a request in milliseconds.
type MetricLatency struct {
	// Total is the end-to-end latency from request receipt to response completion.
	Total float64
	// Gateway is the time spent in gateway processing (Total - Upstream).
	Gateway float64
	// Upstream is the time spent waiting for the upstream response.
	Upstream float64
}

// MetricAttributes holds metric labels for RED metrics.
type MetricAttributes struct {
	// APIID is the unique identifier for the API.
	APIID string
	// APIName is the human-readable name of the API.
	APIName string
	// OrgID is the organization identifier.
	OrgID string
	// Method is the HTTP method (GET, POST, etc.).
	Method string
	// Path is the API listen path.
	Path string
	// ResponseCode is the HTTP response status code.
	ResponseCode int
}

// MetricsRecorder records RED (Rate, Errors, Duration) metrics for the gateway.
// It provides a single Record() method that handlers call with timing data.
type MetricsRecorder struct {
	requestCounter  *tykmetric.Counter
	errorCounter    *tykmetric.Counter
	totalLatency    *tykmetric.Histogram
	gatewayLatency  *tykmetric.Histogram
	upstreamLatency *tykmetric.Histogram
	enabled         bool
}

// NewMetricsRecorder creates a new MetricsRecorder using the given MeterProvider.
// If the provider is disabled, returns a noop recorder.
func NewMetricsRecorder(provider MeterProvider) (*MetricsRecorder, error) {
	if provider == nil || !provider.Enabled() {
		return &MetricsRecorder{enabled: false}, nil
	}

	requestCounter, err := provider.NewCounter(
		metricRequestTotal,
		"Total number of HTTP requests",
		unitDimensionless,
	)
	if err != nil {
		return nil, err
	}

	errorCounter, err := provider.NewCounter(
		metricRequestErrors,
		"Total number of HTTP requests that resulted in an error (status >= 400)",
		unitDimensionless,
	)
	if err != nil {
		return nil, err
	}

	totalLatency, err := provider.NewHistogram(
		metricRequestDuration,
		"Total end-to-end request latency in milliseconds",
		unitMilliseconds,
		tykmetric.DefaultLatencyBuckets,
	)
	if err != nil {
		return nil, err
	}

	gatewayLatency, err := provider.NewHistogram(
		metricGatewayLatency,
		"Gateway processing time in milliseconds",
		unitMilliseconds,
		tykmetric.DefaultLatencyBuckets,
	)
	if err != nil {
		return nil, err
	}

	upstreamLatency, err := provider.NewHistogram(
		metricUpstreamLatency,
		"Upstream response time in milliseconds",
		unitMilliseconds,
		tykmetric.DefaultLatencyBuckets,
	)
	if err != nil {
		return nil, err
	}

	return &MetricsRecorder{
		requestCounter:  requestCounter,
		errorCounter:    errorCounter,
		totalLatency:    totalLatency,
		gatewayLatency:  gatewayLatency,
		upstreamLatency: upstreamLatency,
		enabled:         true,
	}, nil
}

// Record records a single request's RED metrics.
// This is the ONLY method handlers need to call.
func (r *MetricsRecorder) Record(ctx context.Context, attrs MetricAttributes, latency MetricLatency) {
	if r == nil || !r.enabled {
		return
	}

	// Build attributes set.
	attrSet := []attribute.KeyValue{
		attribute.String("tyk.api.id", attrs.APIID),
		attribute.String("tyk.api.name", attrs.APIName),
		attribute.String("tyk.api.org_id", attrs.OrgID),
		attribute.String("http.request.method", attrs.Method),
		attribute.String("http.route", attrs.Path),
		attribute.Int("http.response.status_code", attrs.ResponseCode),
	}

	// Record request count (Rate).
	r.requestCounter.Add(ctx, 1, attrSet...)

	// Record error count (Errors) if status >= 400.
	if attrs.ResponseCode >= 400 {
		r.errorCounter.Add(ctx, 1, attrSet...)
	}

	// Record duration metrics (Duration).
	r.totalLatency.Record(ctx, latency.Total, attrSet...)
	r.gatewayLatency.Record(ctx, latency.Gateway, attrSet...)
	r.upstreamLatency.Record(ctx, latency.Upstream, attrSet...)
}

// Enabled returns whether the recorder is enabled.
func (r *MetricsRecorder) Enabled() bool {
	return r != nil && r.enabled
}

// InitOpenTelemetryMetrics initializes OpenTelemetry metrics - it returns a MeterProvider
// which can be used to create a MetricsRecorder. If OpenTelemetry is disabled or metrics are not
// enabled, a NoopProvider is returned.
func InitOpenTelemetryMetrics(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry, id string, version string,
	useRPC bool, groupID string, isSegmented bool, segmentTags []string) MeterProvider {

	metricLogger := logger.WithFields(logrus.Fields{
		"component":       "metrics",
		"exporter":        gwConfig.Exporter,
		"endpoint":        gwConfig.Endpoint,
		"export_interval": gwConfig.Metrics.ExportInterval,
	})

	provider, errOtel := tykmetric.NewProvider(
		tykmetric.WithContext(ctx),
		tykmetric.WithConfig(gwConfig),
		tykmetric.WithLogger(metricLogger),
		tykmetric.WithServiceID(id),
		tykmetric.WithServiceVersion(version),
		tykmetric.WithHostDetector(),
		tykmetric.WithContainerDetector(),
		tykmetric.WithProcessDetector(),
		tykmetric.WithCustomResourceAttributes(GatewayMetricResourceAttributes(
			id,
			useRPC,
			groupID,
			isSegmented,
			segmentTags,
		)...),
	)

	if errOtel != nil {
		logger.Errorf("Initializing OpenTelemetry Metrics: %s", errOtel)
	}

	return provider
}

// GatewayMetricResourceAttributes returns custom attributes for the gateway resource in metrics.
func GatewayMetricResourceAttributes(gwID string, isDataplane bool, groupID string, isSegmented bool, segmentTags []string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 4)

	attrs = append(attrs, attribute.String("tyk.gateway.id", gwID))
	attrs = append(attrs, attribute.Bool("tyk.gateway.dataplane", isDataplane))

	if isDataplane && groupID != "" {
		attrs = append(attrs, attribute.String("tyk.gateway.group_id", groupID))
	}

	if isSegmented && len(segmentTags) > 0 {
		attrs = append(attrs, attribute.StringSlice("tyk.gateway.segment_tags", segmentTags))
	}

	return attrs
}
