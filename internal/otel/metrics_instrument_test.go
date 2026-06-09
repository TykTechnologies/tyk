package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/opentelemetry/metric/metrictest"

	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// noopProvider creates a disabled provider suitable for unit tests.
func noopProvider(t *testing.T) *MetricInstruments {
	t.Helper()
	cfg := &MetricsConfig{} // nil Enabled → noop
	provider, err := NewMetricProvider(context.Background(), logrus.New(), &cfg.BaseMetricsConfig, "test-node", "v0.0.0-test", false, "", false, nil)
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

// --- Happy path tests with active provider ---

// activeProvider creates an instruments set backed by a real ManualReader,
// so recorded values can be collected and asserted.
func activeProvider(t *testing.T) (*MetricInstruments, *metrictest.TestProvider) {
	t.Helper()
	tp := metrictest.NewProvider(t)
	inst := NewMetricInstruments(tp, logrus.New())
	return inst, tp
}

func TestRecordRequest_CountsCorrectly(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	for range 7 {
		inst.RecordRequest(ctx)
	}

	m := tp.FindMetric(t, "tyk.http.requests")
	metrictest.AssertSum(t, m, int64(7))
}

func TestRecordConfigState_SetsGauges(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	inst.RecordConfigState(ctx, 12, 5)

	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.apis.loaded"), float64(12))
	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.policies.loaded"), float64(5))
}

func TestRecordConfigState_UpdatesGauges(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	inst.RecordConfigState(ctx, 3, 1)
	inst.RecordConfigState(ctx, 8, 4)

	// Gauges reflect the latest value, not a sum.
	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.apis.loaded"), float64(8))
	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.policies.loaded"), float64(4))
}

func TestRecordReload_CounterAndHistogram(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	inst.RecordReload(ctx, 250*time.Millisecond)

	metrictest.AssertSum(t, tp.FindMetric(t, "tyk.gateway.config.reload"), int64(1))
	metrictest.AssertHistogramCount(t, tp.FindMetric(t, "tyk.gateway.config.reload.duration"), uint64(1))
	metrictest.AssertHistogramSum(t, tp.FindMetric(t, "tyk.gateway.config.reload.duration"), 0.25)
}

func TestRecordReload_Accumulates(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	inst.RecordReload(ctx, 100*time.Millisecond)
	inst.RecordReload(ctx, 200*time.Millisecond)
	inst.RecordReload(ctx, 500*time.Millisecond)

	metrictest.AssertSum(t, tp.FindMetric(t, "tyk.gateway.config.reload"), int64(3))
	metrictest.AssertHistogramCount(t, tp.FindMetric(t, "tyk.gateway.config.reload.duration"), uint64(3))
	metrictest.AssertHistogramSum(t, tp.FindMetric(t, "tyk.gateway.config.reload.duration"), 0.8)
}

func TestSetRegistry(t *testing.T) {
	tests := []struct {
		name            string
		defs            []apimetrics.APIMetricDefinition
		wantPanic       bool
		needsSession    bool
		needsContext    bool
		needsResponse   bool
		needsConfigData bool
		wantMetric      string // if non-empty, record a request and assert this counter exists
	}{
		{
			name: "metadata dimension registers and records",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "test.metadata",
				Type: "counter",
				Dimensions: []apimetrics.DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				},
			}},
			wantMetric: "test.metadata",
		},
		{
			name: "response_header dimension sets NeedsResponse",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "test.resp.header",
				Type: "counter",
				Dimensions: []apimetrics.DimensionDefinition{
					{Source: "response_header", Key: "X-Version", Label: "version", Default: "unknown"},
				},
			}},
			needsResponse: true,
			wantMetric:    "test.resp.header",
		},
		{
			name: "session dimension sets NeedsSession",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "test.session",
				Type: "counter",
				Dimensions: []apimetrics.DimensionDefinition{
					{Source: "session", Key: "oauth_id", Label: "oauth"},
				},
			}},
			needsSession: true,
			wantMetric:   "test.session",
		},
		{
			name: "context dimension sets NeedsContext",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "test.context",
				Type: "counter",
				Dimensions: []apimetrics.DimensionDefinition{
					{Source: "context", Key: "tier", Label: "tier", Default: "basic"},
				},
			}},
			needsContext: true,
			wantMetric:   "test.context",
		},
		{
			name: "config_data dimension sets NeedsConfigData",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "test.config_data",
				Type: "counter",
				Dimensions: []apimetrics.DimensionDefinition{
					{Source: "config_data", Key: "environment", Label: "env", Default: "unknown"},
				},
			}},
			needsConfigData: true,
			wantMetric:      "test.config_data",
		},
		{
			name: "invalid definition panics",
			defs: []apimetrics.APIMetricDefinition{{
				Name: "",
				Type: "counter",
			}},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, tp := activeProvider(t)

			if tt.wantPanic {
				assert.Panics(t, func() {
					inst.SetRegistry(tp, tt.defs)
				})
				return
			}

			inst.SetRegistry(tp, tt.defs)

			assert.Equal(t, tt.needsSession, inst.NeedsSession())
			assert.Equal(t, tt.needsContext, inst.NeedsContext())
			assert.Equal(t, tt.needsResponse, inst.NeedsResponse())
			assert.Equal(t, tt.needsConfigData, inst.NeedsConfigData())

			if tt.wantMetric != "" {
				rc := &apimetrics.RequestContext{
					Request:    httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
					StatusCode: 200,
					APIID:      "api-1",
				}
				inst.RecordAPIMetrics(context.Background(), rc)

				m := tp.FindMetric(t, tt.wantMetric)
				metrictest.AssertSum(t, m, int64(1))
			}
		})
	}
}

func TestAllMetricNames_Registered(t *testing.T) {
	inst, tp := activeProvider(t)
	ctx := context.Background()

	// Exercise every instrument so they appear in the collection.
	inst.RecordRequest(ctx)
	inst.RecordConfigState(ctx, 1, 1)
	inst.RecordReload(ctx, time.Millisecond)

	names := tp.MetricNames()
	expected := []string{
		"tyk.http.requests",
		"tyk.gateway.apis.loaded",
		"tyk.gateway.policies.loaded",
		"tyk.gateway.config.reload",
		"tyk.gateway.config.reload.duration",
	}
	for _, name := range expected {
		assert.Contains(t, names, name)
	}
}
