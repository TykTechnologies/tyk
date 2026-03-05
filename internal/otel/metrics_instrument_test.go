package otel

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopProvider creates a disabled provider suitable for unit tests.
func noopProvider(t *testing.T) *MetricInstruments {
	t.Helper()
	cfg := &MetricsConfig{} // nil Enabled → noop
	provider, err := NewMetricProvider(context.Background(), logrus.New(), &cfg.BaseMetricsConfig, "test-node", "v0.0.0-test")
	require.NoError(t, err)
	return NewMetricInstruments(provider, logrus.New())
}

// runConcurrent launches n goroutines each calling fn iter times,
// then waits for all to complete.
func runConcurrent(n, iter int, fn func()) {
	done := make(chan struct{})
	for range n {
		go func() {
			defer func() { done <- struct{}{} }()
			for range iter {
				fn()
			}
		}()
	}
	for range n {
		<-done
	}
}

func TestNewMetricInstruments(t *testing.T) {
	inst := noopProvider(t)
	assert.NotNil(t, inst)
	assert.NotNil(t, inst.provider)
	assert.NotNil(t, inst.requestCounter)
}

func TestNewMetricInstruments_ConfigFields(t *testing.T) {
	inst := noopProvider(t)
	assert.NotNil(t, inst.apisLoaded)
	assert.NotNil(t, inst.policiesLoaded)
	assert.NotNil(t, inst.reloadCounter)
	assert.NotNil(t, inst.reloadDuration)
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

	runConcurrent(10, 100, func() {
		inst.RecordRequest(ctx)
	})
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

func TestRecordConfigState_Noop(t *testing.T) {
	inst := noopProvider(t)

	// Must not panic on noop provider
	require.NotPanics(t, func() {
		inst.RecordConfigState(context.Background(), 5, 3)
	})
}

func TestRecordReload_Noop(t *testing.T) {
	inst := noopProvider(t)

	// Must not panic on noop provider
	require.NotPanics(t, func() {
		inst.RecordReload(context.Background(), 250*time.Millisecond)
	})
}

func TestRecordConfigState_Concurrent(t *testing.T) {
	inst := noopProvider(t)
	ctx := context.Background()

	runConcurrent(10, 100, func() {
		inst.RecordConfigState(ctx, 10, 5)
	})
}

func TestRecordReload_Concurrent(t *testing.T) {
	inst := noopProvider(t)
	ctx := context.Background()

	runConcurrent(10, 100, func() {
		inst.RecordReload(ctx, 100*time.Millisecond)
	})
}
