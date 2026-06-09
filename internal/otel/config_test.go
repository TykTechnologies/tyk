package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
					BaseMetricsConfig: BaseMetricsConfig{
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
					BaseMetricsConfig: BaseMetricsConfig{
						ExporterConfig: ExporterConfig{
							Endpoint: "metrics-only:9090",
						},
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
					BaseMetricsConfig: BaseMetricsConfig{
						ExporterConfig: ExporterConfig{
							Headers: map[string]string{}, // non-nil empty map
						},
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
					BaseMetricsConfig: BaseMetricsConfig{
						ExporterConfig: ExporterConfig{
							TLS: otelconfig.TLS{
								CAFile: "/metrics-ca.pem",
							},
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
					BaseMetricsConfig: BaseMetricsConfig{
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
		{
			name: "cardinality_limit defaults to 2000",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, 2000, got.Metrics.CardinalityLimit)
			},
		},
		{
			name: "cardinality_limit preserves explicit value",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						CardinalityLimit: 500,
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, 500, got.Metrics.CardinalityLimit)
			},
		},
		{
			name: "negative cardinality_limit preserved (disables limit)",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						CardinalityLimit: -1,
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, -1, got.Metrics.CardinalityLimit)
			},
		},

		// ---- New format (Traces sub-object) tests ----
		{
			name: "new format: both traces and metrics enabled independently",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: true,
						ExporterConfig: ExporterConfig{
							Exporter: "grpc",
							Endpoint: "trace-collector:4317",
						},
					},
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
						ExporterConfig: ExporterConfig{
							Endpoint: "metrics-collector:4318",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.True(t, got.TracesEnabled())
				assert.True(t, got.Traces.Enabled)
				require.NotNil(t, got.Metrics.Enabled)
				assert.True(t, *got.Metrics.Enabled)

				// Traces config got defaults applied
				assert.Equal(t, "grpc", got.Traces.Exporter)
				assert.Equal(t, "trace-collector:4317", got.Traces.Endpoint)

				// Metrics kept its own endpoint, inherited exporter from traces
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "metrics-collector:4318", got.Metrics.Endpoint)

				// Root-level fields remain at zero (not used in new format)
				assert.False(t, got.Enabled)
			},
		},
		{
			name: "new format: traces only, metrics disabled",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: true,
						ExporterConfig: ExporterConfig{
							Exporter: "http",
							Endpoint: "collector:4318",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.True(t, got.TracesEnabled())
				assert.Nil(t, got.Metrics.Enabled)
			},
		},
		{
			name: "new format: metrics only, traces disabled",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: false,
					},
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
						ExporterConfig: ExporterConfig{
							Exporter: "grpc",
							Endpoint: "metrics-collector:4317",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.False(t, got.TracesEnabled())
				require.NotNil(t, got.Metrics.Enabled)
				assert.True(t, *got.Metrics.Enabled)
				assert.Equal(t, "metrics-collector:4317", got.Metrics.Endpoint)
			},
		},
		{
			name: "legacy format: root-level trace fields, no Traces key",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter: "grpc",
						Endpoint: "collector:4317",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.True(t, got.TracesEnabled())
				assert.Nil(t, got.Traces)
				assert.Equal(t, "grpc", got.Exporter)
				assert.Equal(t, "collector:4317", got.Endpoint)
				// Metrics inherits from root-level trace
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "collector:4317", got.Metrics.Endpoint)
			},
		},
		{
			name: "legacy + metrics: root-level trace + metrics",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter: "grpc",
						Endpoint: "collector:4317",
					},
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.True(t, got.TracesEnabled())
				assert.Nil(t, got.Traces)
				require.NotNil(t, got.Metrics.Enabled)
				assert.True(t, *got.Metrics.Enabled)
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "collector:4317", got.Metrics.Endpoint)
			},
		},
		{
			name: "conflict: root + Traces present, Traces wins",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: false,
					ExporterConfig: ExporterConfig{
						Exporter: "http",
						Endpoint: "root-collector:4318",
					},
				},
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: true,
						ExporterConfig: ExporterConfig{
							Exporter: "grpc",
							Endpoint: "traces-collector:4317",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// Traces sub-object wins
				assert.True(t, got.TracesEnabled())
				assert.Equal(t, "grpc", got.EffectiveTraceConfig().Exporter)
				assert.Equal(t, "traces-collector:4317", got.EffectiveTraceConfig().Endpoint)
				// Root-level fields remain unchanged
				assert.False(t, got.Enabled)
				assert.Equal(t, "http", got.Exporter)
			},
		},
		{
			name: "metrics inherits from Traces (new format)",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: true,
						ExporterConfig: ExporterConfig{
							Exporter:          "grpc",
							Endpoint:          "custom-collector:4317",
							ConnectionTimeout: 10,
							ResourceName:      "custom-gw",
						},
					},
				},
				// Metrics left at zero — should inherit from Traces.
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "custom-collector:4317", got.Metrics.Endpoint)
				assert.Equal(t, 10, got.Metrics.ConnectionTimeout)
				assert.Equal(t, "custom-gw", got.Metrics.ResourceName)
			},
		},
		{
			name: "metrics inherits from root (legacy)",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled: true,
					ExporterConfig: ExporterConfig{
						Exporter:          "http",
						Endpoint:          "legacy-collector:4318",
						ConnectionTimeout: 7,
						ResourceName:      "legacy-gw",
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "http", got.Metrics.Exporter)
				assert.Equal(t, "legacy-collector:4318", got.Metrics.Endpoint)
				assert.Equal(t, 7, got.Metrics.ConnectionTimeout)
				assert.Equal(t, "legacy-gw", got.Metrics.ResourceName)
			},
		},
		{
			name: "SetDefaults completeness: minimal Traces enabled",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: true,
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				// Trace defaults applied to Traces sub-object
				assert.Equal(t, "grpc", got.Traces.Exporter)
				assert.Equal(t, "localhost:4317", got.Traces.Endpoint)
				assert.Equal(t, 1, got.Traces.ConnectionTimeout)
				assert.Equal(t, "tyk", got.Traces.ResourceName)

				// Metrics inherits trace defaults
				assert.Equal(t, "grpc", got.Metrics.Exporter)
				assert.Equal(t, "localhost:4317", got.Metrics.Endpoint)
				assert.Equal(t, 1, got.Metrics.ConnectionTimeout)

				// Metrics-specific defaults also applied
				assert.Equal(t, 60, got.Metrics.ExportInterval)
				assert.Equal(t, "cumulative", got.Metrics.Temporality)
			},
		},
		{
			name: "metrics standalone: no traces config at all",
			input: OpenTelemetry{
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
						ExporterConfig: ExporterConfig{
							Exporter: "grpc",
							Endpoint: "metrics-only:4317",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.False(t, got.TracesEnabled())
				require.NotNil(t, got.Metrics.Enabled)
				assert.True(t, *got.Metrics.Enabled)
				assert.Equal(t, "metrics-only:4317", got.Metrics.Endpoint)
				assert.Equal(t, 60, got.Metrics.ExportInterval)
				assert.Equal(t, "cumulative", got.Metrics.Temporality)
			},
		},
		{
			name: "metrics standalone: traces disabled explicitly",
			input: OpenTelemetry{
				Traces: &TracesConfig{
					BaseOpenTelemetry: BaseOpenTelemetry{
						Enabled: false,
					},
				},
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
						ExporterConfig: ExporterConfig{
							Exporter: "grpc",
							Endpoint: "metrics-only:4317",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.False(t, got.TracesEnabled())
				require.NotNil(t, got.Metrics.Enabled)
				assert.True(t, *got.Metrics.Enabled)
				assert.Equal(t, "metrics-only:4317", got.Metrics.Endpoint)
				// Metrics-specific defaults applied
				assert.Equal(t, 60, got.Metrics.ExportInterval)
				assert.Equal(t, 2000, got.Metrics.CardinalityLimit)
			},
		},
		{
			name: "metrics own exporter, no traces",
			input: OpenTelemetry{
				Metrics: MetricsConfig{
					BaseMetricsConfig: BaseMetricsConfig{
						Enabled: boolPtr(true),
						ExporterConfig: ExporterConfig{
							Exporter: "http",
							Endpoint: "metrics-own:4318",
						},
					},
				},
			},
			assert: func(t *testing.T, got *OpenTelemetry) {
				t.Helper()
				assert.Equal(t, "http", got.Metrics.Exporter)
				assert.Equal(t, "metrics-own:4318", got.Metrics.Endpoint)
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

func TestOpenTelemetry_TracesEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    OpenTelemetry
		expected bool
	}{
		{
			name:     "legacy: root enabled=true",
			input:    OpenTelemetry{BaseOpenTelemetry: BaseOpenTelemetry{Enabled: true}},
			expected: true,
		},
		{
			name:     "legacy: root enabled=false",
			input:    OpenTelemetry{BaseOpenTelemetry: BaseOpenTelemetry{Enabled: false}},
			expected: false,
		},
		{
			name: "new format: Traces enabled=true, root enabled=false",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{Enabled: false},
				Traces:            &TracesConfig{BaseOpenTelemetry: BaseOpenTelemetry{Enabled: true}},
			},
			expected: true,
		},
		{
			name: "Traces disabled, root enabled: root wins (handles envconfig allocation)",
			input: OpenTelemetry{
				BaseOpenTelemetry: BaseOpenTelemetry{Enabled: true},
				Traces:            &TracesConfig{BaseOpenTelemetry: BaseOpenTelemetry{Enabled: false}},
			},
			expected: true,
		},
		{
			name:     "zero value: everything default",
			input:    OpenTelemetry{},
			expected: false,
		},
		{
			name: "new format: Traces present but enabled=false",
			input: OpenTelemetry{
				Traces: &TracesConfig{BaseOpenTelemetry: BaseOpenTelemetry{Enabled: false}},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.TracesEnabled())
		})
	}
}

func TestOpenTelemetry_EffectiveTraceConfig(t *testing.T) {
	t.Run("returns Traces config when present and enabled", func(t *testing.T) {
		cfg := OpenTelemetry{
			BaseOpenTelemetry: BaseOpenTelemetry{
				ExporterConfig: ExporterConfig{Endpoint: "root-endpoint"},
			},
			Traces: &TracesConfig{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled:        true,
					ExporterConfig: ExporterConfig{Endpoint: "traces-endpoint"},
				},
			},
		}
		assert.Equal(t, "traces-endpoint", cfg.EffectiveTraceConfig().Endpoint)
	})

	t.Run("returns root config when Traces present but disabled", func(t *testing.T) {
		cfg := OpenTelemetry{
			BaseOpenTelemetry: BaseOpenTelemetry{
				ExporterConfig: ExporterConfig{Endpoint: "root-endpoint"},
			},
			Traces: &TracesConfig{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled:        false,
					ExporterConfig: ExporterConfig{Endpoint: "traces-endpoint"},
				},
			},
		}
		assert.Equal(t, "root-endpoint", cfg.EffectiveTraceConfig().Endpoint)
	})

	t.Run("returns root config when Traces is nil", func(t *testing.T) {
		cfg := OpenTelemetry{
			BaseOpenTelemetry: BaseOpenTelemetry{
				ExporterConfig: ExporterConfig{Endpoint: "root-endpoint"},
			},
		}
		assert.Equal(t, "root-endpoint", cfg.EffectiveTraceConfig().Endpoint)
	})

	t.Run("LibraryConfig returns same as EffectiveTraceConfig", func(t *testing.T) {
		cfg := OpenTelemetry{
			Traces: &TracesConfig{
				BaseOpenTelemetry: BaseOpenTelemetry{
					Enabled:        true,
					ExporterConfig: ExporterConfig{Endpoint: "traces-endpoint"},
				},
			},
		}
		assert.Equal(t, cfg.EffectiveTraceConfig(), cfg.LibraryConfig())
	})
}
