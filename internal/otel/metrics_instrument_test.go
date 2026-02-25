package otel

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopProvider creates a disabled provider suitable for unit tests.
func noopProvider(t *testing.T) *MetricInstruments {
	t.Helper()
	cfg := &MetricsConfig{} // nil Enabled → noop
	provider, err := NewMetricProvider(context.Background(), logrus.New(), cfg, "test-node", "v0.0.0-test")
	require.NoError(t, err)
	return NewMetricInstruments(provider, logrus.New())
}

func TestNewMetricInstruments(t *testing.T) {
	inst := noopProvider(t)
	assert.NotNil(t, inst)
	assert.NotNil(t, inst.provider)
	assert.NotNil(t, inst.requestCounter)
}

func TestRecordRequest_Noop(t *testing.T) {
	inst := noopProvider(t)

	// Must not panic on noop provider
	require.NotPanics(t, func() {
		inst.RecordRequest(context.Background())
	})
}

func TestRecordRequest_Concurrent(t *testing.T) {
	inst := noopProvider(t)
	ctx := context.Background()

	// Concurrent calls must not race or panic
	done := make(chan struct{})
	for range 10 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 100 {
				inst.RecordRequest(ctx)
			}
		}()
	}
	for range 10 {
		<-done
	}
}

func TestShutdown_Noop(t *testing.T) {
	inst := noopProvider(t)
	assert.NoError(t, inst.Shutdown(context.Background()))
}

func TestShutdown_Idempotent(t *testing.T) {
	inst := noopProvider(t)
	ctx := context.Background()

	// Calling Shutdown twice must not panic or error on noop
	require.NoError(t, inst.Shutdown(ctx))
	require.NotPanics(t, func() {
		//nolint:errcheck // second shutdown may error; we only assert no panic
		inst.Shutdown(ctx)
	})
}
