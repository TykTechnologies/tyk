package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
)

func boolPtr(v bool) *bool { return &v }

func TestOpenTelemetry_SetDefaults(t *testing.T) {
	tests := []struct {
		name   string
		input  OpenTelemetry
		assert func(t *testing.T, got *OpenTelemetry)
	}{
		{
			name: "metrics inherits all trace exporter fields when zero",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter:          "http",
						Endpoint:          "collector:4318",
						Headers:           map[string]string{"Authorization": "Bearer tok"},
						ConnectionTimeout: 10,
						ResourceName:      "my-gateway",
						TLS: otelconfig.TLS{
							Enable: true,
							CAFile: "/ca.pem",
						},
					},
				},
				// Metrics left at zero — should inherit everything.
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "http", got.Metrics.Exporter)
				assert.Equal(t, "collector:4318", got.Metrics.Endpoint)
				assert.Equal(t, map[string]string{"Authorization": "Bearer tok"}, got.Metrics.Headers)
				assert.Equal(t, 10, got.Metrics.ConnectionTimeout)
				assert.Equal(t, "my-gateway", got.Metrics.ResourceName)
				assert.True(t, got.Metrics.TLS.Enable)
				assert.Equal(t, "/ca.pem", got.Metrics.TLS.CAFile)
			},
		},
		{
			name: "metrics explicit values are preserved",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter:          "grpc",
						Endpoint:          "trace-collector:4317",
						Headers:           map[string]string{"X-Trace": "1"},
						ConnectionTimeout: 5,
						ResourceName:      "trace-gw",
						TLS: otelconfig.TLS{
							Enable: true,
							CAFile: "/trace-ca.pem",
						},
					},
				},
				Metrics: MetricsConfig{
					ExporterConfig: ExporterConfig{
						Exporter:          "http",
						Endpoint:          "metrics-collector:4318",
						Headers:           map[string]string{"X-Metrics": "1"},
						ConnectionTimeout: 20,
						ResourceName:      "metrics-gw",
						TLS: otelconfig.TLS{
							Enable:   true,
							CertFile: "/metrics-cert.pem",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "http", got.Metrics.Exporter)
				assert.Equal(t, "metrics-collector:4318", got.Metrics.Endpoint)
				assert.Equal(t, map[string]string{"X-Metrics": "1"}, got.Metrics.Headers)
				assert.Equal(t, 20, got.Metrics.ConnectionTimeout)
				assert.Equal(t, "metrics-gw", got.Metrics.ResourceName)
				assert.Equal(t, "/metrics-cert.pem", got.Metrics.TLS.CertFile)
				// CAFile must NOT leak from trace.
				assert.Empty(t, got.Metrics.TLS.CAFile)
			},
		},
		{
			name: "partial metrics fields inherit only missing",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter:          "grpc",
						Endpoint:          "shared-collector:4317",
						ConnectionTimeout: 5,
						ResourceName:      "shared-gw",
					},
				},
				Metrics: MetricsConfig{
					ExporterConfig: ExporterConfig{
						Endpoint: "metrics-only:9090",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "grpc", got.Metrics.Exporter, "inherited from trace")
				assert.Equal(t, "metrics-only:9090", got.Metrics.Endpoint, "kept explicit value")
				assert.Equal(t, 5, got.Metrics.ConnectionTimeout, "inherited from trace")
				assert.Equal(t, "shared-gw", got.Metrics.ResourceName, "inherited from trace")
			},
		},
		{
			name: "nil metrics headers inherits trace headers",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Headers: map[string]string{"X-Api-Key": "secret"},
					},
				},
				// Metrics.Headers is nil by default.
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, map[string]string{"X-Api-Key": "secret"}, got.Metrics.Headers)
			},
		},
		{
			name: "explicit empty metrics headers not overridden",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Headers: map[string]string{"X-Api-Key": "secret"},
					},
				},
				Metrics: MetricsConfig{
					ExporterConfig: ExporterConfig{
						Headers: map[string]string{}, // non-nil empty map
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.NotNil(t, got.Metrics.Headers)
				assert.Empty(t, got.Metrics.Headers)
			},
		},
		{
			name: "disabled trace skips base defaults but still inherits",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: false,
					ExporterConfig: ExporterConfig{
						Exporter: "grpc",
						Endpoint: "collector:4317",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// BaseOpenTelemetry.SetDefaults is a no-op when disabled,
				// but inheritance still copies what trace already has.
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "collector:4317", got.Metrics.Endpoint)
			},
		},
		{
			name: "library defaults propagate through inheritance",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// Trace library defaults should propagate to metrics.
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "localhost:4317", got.Metrics.Endpoint)
				assert.Equal(t, 1, got.Metrics.ConnectionTimeout)
				assert.Equal(t, "tyk", got.Metrics.ResourceName)

				// Metrics-specific library defaults also applied.
				assert.Equal(t, 60, got.Metrics.ExportInterval)
				assert.Equal(t, "cumulative", got.Metrics.Temporality)
				assert.Equal(t, 30, got.Metrics.ShutdownTimeout)
				assert.NotNil(t, got.Metrics.Retry.Enabled)
				assert.True(t, *got.Metrics.Retry.Enabled)
			},
		},
		{
			name: "TLS not inherited when metrics TLS is non-zero",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						TLS: otelconfig.TLS{
							Enable:             true,
							InsecureSkipVerify: true,
							CAFile:             "/trace-ca.pem",
						},
					},
				},
				Metrics: MetricsConfig{
					ExporterConfig: ExporterConfig{
						TLS: otelconfig.TLS{
							CAFile: "/metrics-ca.pem",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// Metrics TLS was non-zero so trace TLS must NOT be copied.
				assert.False(t, got.Metrics.TLS.Enable)
				assert.Equal(t, "/metrics-ca.pem", got.Metrics.TLS.CAFile)
				assert.False(t, got.Metrics.TLS.InsecureSkipVerify)
			},
		},
		{
			name: "trace defaults do not clobber pre-set trace fields",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						ResourceName: "custom-gw",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// ResourceName was pre-set so base SetDefaults must not overwrite.
				assert.Equal(t, "custom-gw", got.ResourceName)
				// Metrics inherits the pre-set value, not the library default "tyk".
				assert.Equal(t, "custom-gw", got.Metrics.ResourceName)
			},
		},
		{
			name: "metrics-specific defaults applied even with full trace config",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter:          "grpc",
						Endpoint:          "collector:4317",
						ConnectionTimeout: 5,
						ResourceName:      "gw",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// Metrics-only fields get library defaults regardless of trace config.
				assert.Equal(t, 60, got.Metrics.ExportInterval)
				assert.Equal(t, "cumulative", got.Metrics.Temporality)
				assert.Equal(t, 30, got.Metrics.ShutdownTimeout)
				assert.NotNil(t, got.Metrics.Retry.Enabled)
				assert.True(t, *got.Metrics.Retry.Enabled)
				assert.Equal(t, 5000, got.Metrics.Retry.InitialInterval)
				assert.Equal(t, 30000, got.Metrics.Retry.MaxInterval)
				assert.Equal(t, 60000, got.Metrics.Retry.MaxElapsedTime)
			},
		},
		{
			name: "metrics-specific defaults not overridden when set",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
				},
				Metrics: MetricsConfig{
					ExportInterval:  15,
					Temporality:     "delta",
					ShutdownTimeout: 5,
					Retry: MetricsRetryConfig{
						Enabled:         boolPtr(false),
						InitialInterval: 1000,
						MaxInterval:     5000,
						MaxElapsedTime:  10000,
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, 15, got.Metrics.ExportInterval)
				assert.Equal(t, "delta", got.Metrics.Temporality)
				assert.Equal(t, 5, got.Metrics.ShutdownTimeout)
				assert.NotNil(t, got.Metrics.Retry.Enabled)
				assert.False(t, *got.Metrics.Retry.Enabled)
				assert.Equal(t, 1000, got.Metrics.Retry.InitialInterval)
				assert.Equal(t, 5000, got.Metrics.Retry.MaxInterval)
				assert.Equal(t, 10000, got.Metrics.Retry.MaxElapsedTime)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.input
			cfg.SetDefaults()
			tt.assert(t, &cfg)
		})
	}
}
