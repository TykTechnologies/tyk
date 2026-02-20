package otel

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
)

func TestInitOpenTelemetryMetrics_Disabled(t *testing.T) {
	// metrics.enabled absent → noop instruments, no error
	cfg := &OpenTelemetry{Enabled: false}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"node-1", "v5.0", false, "", false, nil)

	// RecordRequest must not panic on noop
	inst.RecordRequest(context.Background())

	// Shutdown must be safe on noop
	assert.NoError(t, inst.Shutdown(context.Background()))
}

func TestInitOpenTelemetryMetrics_Enabled(t *testing.T) {
	// Both enabled=true and metrics.enabled=true → active provider
	metricsEnabled := true
	cfg := &OpenTelemetry{
		Enabled:  true,
		Exporter: "grpc",
		Endpoint: "localhost:4317",
		Metrics: otelconfig.MetricsConfig{
			Enabled:        &metricsEnabled,
			ExportInterval: 60,
		},
	}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"node-1", "v5.0", false, "", false, nil)

	// RecordRequest must not panic
	inst.RecordRequest(context.Background())

	// Shutdown flushes and stops — may fail if no collector is running,
	// but must not panic
	require.NotPanics(t, func() {
		//nolint:errcheck // shutdown may fail without a running collector; we only assert no panic
		inst.Shutdown(context.Background())
	})
}

func TestRecordRequest_NilSafe(t *testing.T) {
	// Verify the Instruments struct handles disabled state gracefully
	cfg := &OpenTelemetry{Enabled: false}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"", "", false, "", false, nil)

	// Call many times — must never panic
	require.NotPanics(t, func() {
		for range 100 {
			inst.RecordRequest(context.Background())
		}
	})
}
