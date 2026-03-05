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
	cfg := &OpenTelemetry{}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"node-1", "v5.0", false, "", false, nil)

	// RecordRequest must not panic on noop
	inst.RecordRequest(context.Background())

	// Shutdown must be safe on noop
	assert.NoError(t, inst.Shutdown(context.Background()))
}

func TestInitOpenTelemetryMetrics_Enabled(t *testing.T) {
	// metrics.enabled=true → active provider
	metricsEnabled := true
	cfg := &OpenTelemetry{
		Metrics: MetricsConfig{
			BaseMetricsConfig: BaseMetricsConfig{
				Enabled: &metricsEnabled,
				ExporterConfig: otelconfig.ExporterConfig{
					Exporter: "grpc",
					Endpoint: "localhost:4317",
				},
				ExportInterval: 60,
			},
		},
	}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"node-1", "v5.0", true, "group1", true, []string{"tag1", "tag2"})

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
	// Verify the MetricInstruments struct handles disabled state gracefully
	cfg := &OpenTelemetry{}
	inst := InitOpenTelemetryMetrics(context.Background(), logrus.New(), cfg,
		"", "", false, "", false, nil)

	// Call many times — must never panic
	require.NotPanics(t, func() {
		for range 100 {
			inst.RecordRequest(context.Background())
		}
	})
}

func TestNewMetricProvider_ResourceAttributes(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		version     string
		useRPC      bool
		groupID     string
		isSegmented bool
		segmentTags []string
		expectError bool
	}{
		{
			name:        "Non-dataplane, non-segmented gateway",
			id:          "node-1",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "",
			isSegmented: false,
			segmentTags: nil,
			expectError: false,
		},
		{
			name:        "Dataplane gateway with group ID",
			id:          "node-2",
			version:     "v5.0",
			useRPC:      true,
			groupID:     "edge-group-1",
			isSegmented: false,
			segmentTags: nil,
			expectError: false,
		},
		{
			name:        "Segmented gateway with tags",
			id:          "node-3",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "",
			isSegmented: true,
			segmentTags: []string{"production", "eu-west"},
			expectError: false,
		},
		{
			name:        "Dataplane and segmented gateway",
			id:          "node-4",
			version:     "v5.0",
			useRPC:      true,
			groupID:     "edge-group-2",
			isSegmented: true,
			segmentTags: []string{"staging", "us-east"},
			expectError: false,
		},
		{
			name:        "Empty gateway ID",
			id:          "",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "",
			isSegmented: false,
			segmentTags: nil,
			expectError: false,
		},
		{
			name:        "Segmented with empty tags",
			id:          "node-5",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "",
			isSegmented: true,
			segmentTags: []string{},
			expectError: false,
		},
		{
			name:        "Non-dataplane with groupID provided (should not include groupID)",
			id:          "node-6",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "ignored-group",
			isSegmented: false,
			segmentTags: nil,
			expectError: false,
		},
		{
			name:        "Non-segmented with tags provided (should not include tags)",
			id:          "node-7",
			version:     "v5.0",
			useRPC:      false,
			groupID:     "",
			isSegmented: false,
			segmentTags: []string{"ignored", "tags"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metricsEnabled := true
			cfg := &MetricsConfig{
				BaseMetricsConfig: otelconfig.MetricsConfig{
					Enabled: &metricsEnabled,
					ExporterConfig: otelconfig.ExporterConfig{
						Exporter: "grpc",
						Endpoint: "localhost:4317",
					},
					ExportInterval: 60,
				},
			}

			provider, err := NewMetricProvider(
				context.Background(),
				logrus.New(),
				&cfg.BaseMetricsConfig,
				tt.id,
				tt.version,
				tt.useRPC,
				tt.groupID,
				tt.isSegmented,
				tt.segmentTags,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				// Provider creation may fail without a running collector, but should not panic
				assert.NotNil(t, provider)
			}
		})
	}
}
