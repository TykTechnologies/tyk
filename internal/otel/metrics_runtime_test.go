package otel

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
)

func TestIsRuntimeMetricsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *MetricsConfig
		expected bool
	}{
		{
			name: "metrics disabled - runtime metrics disabled",
			cfg: &MetricsConfig{
				Enabled: nil, // nil = disabled
			},
			expected: false,
		},
		{
			name: "metrics enabled, runtime metrics nil (not set by SetDefaults)",
			cfg: &MetricsConfig{
				Enabled:        boolPtr(true),
				RuntimeMetrics: nil,
			},
			expected: false, // SetDefaults should be called to set this to true
		},
		{
			name: "metrics enabled, runtime_metrics explicitly true",
			cfg: &MetricsConfig{
				Enabled:        boolPtr(true),
				RuntimeMetrics: boolPtr(true),
			},
			expected: true,
		},
		{
			name: "metrics enabled, runtime_metrics explicitly false",
			cfg: &MetricsConfig{
				Enabled:        boolPtr(true),
				RuntimeMetrics: boolPtr(false),
			},
			expected: false,
		},
		{
			name: "metrics disabled, runtime_metrics explicitly true",
			cfg: &MetricsConfig{
				Enabled:        boolPtr(false),
				RuntimeMetrics: boolPtr(true),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRuntimeMetricsEnabled(tt.cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInitOpenTelemetryMetrics_RuntimeMetricsEnabled(t *testing.T) {
	metricsEnabled := true
	cfg := &OpenTelemetry{
		Metrics: MetricsConfig{
			Enabled: &metricsEnabled,
			ExporterConfig: otelconfig.ExporterConfig{
				Exporter: "grpc",
				Endpoint: "localhost:4317",
			},
			ExportInterval: 60,
			// RuntimeMetrics defaults to true when not set
		},
	}

	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg, "test-node", "v1.0.0")
	assert.NotNil(t, inst)
	assert.NotNil(t, inst.provider)

	_ = inst.Shutdown(context.Background())
}

func TestInitOpenTelemetryMetrics_RuntimeMetricsDisabled(t *testing.T) {
	metricsEnabled := true
	runtimeMetricsDisabled := false
	cfg := &OpenTelemetry{
		Metrics: MetricsConfig{
			Enabled: &metricsEnabled,
			ExporterConfig: otelconfig.ExporterConfig{
				Exporter: "grpc",
				Endpoint: "localhost:4317",
			},
			ExportInterval: 60,
			RuntimeMetrics: &runtimeMetricsDisabled,
		},
	}

	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg, "test-node", "v1.0.0")
	assert.NotNil(t, inst)
	assert.NotNil(t, inst.provider)

	_ = inst.Shutdown(context.Background())
}

func TestInitOpenTelemetryMetrics_MetricsDisabled(t *testing.T) {
	cfg := &OpenTelemetry{
		Metrics: MetricsConfig{
			Enabled: nil,
		},
	}

	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg, "test-node", "v1.0.0")
	assert.NotNil(t, inst)

	// Should not panic
	inst.RecordRequest(context.Background())

	_ = inst.Shutdown(context.Background())
}
