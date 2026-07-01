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
	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// Verifies: STK-REQ-093, SYS-REQ-181, SW-REQ-168
// SW-REQ-168:nominal:nominal
// SW-REQ-168:boundary:nominal
// SW-REQ-168:error_handling:nominal
// SW-REQ-168:encoding_safety:nominal
// SW-REQ-168:determinism:nominal
// SYS-REQ-181:determinism:nominal
// MCDC SYS-REQ-181: otel_api_metric_delegation_determined=T, otel_metric_provider_instruments_determined=T, otel_metric_recording_determined=T, otel_resource_attributes_determined=T, otel_runtime_metrics_enablement_determined=T, otel_span_context_helpers_determined=T, otel_trace_config_defaults_determined=T, otel_trace_provider_fallback_determined=T => TRUE
// MCDC SW-REQ-168: otel_api_metric_delegation_determined=T, otel_metric_provider_instruments_determined=T, otel_metric_recording_determined=T, otel_resource_attributes_determined=T, otel_runtime_metrics_enablement_determined=T, otel_span_context_helpers_determined=T, otel_trace_config_defaults_determined=T, otel_trace_provider_fallback_determined=T => TRUE
func TestOTelRuntimeLocalBehaviorReqProof(t *testing.T) {
	cfg := OpenTelemetry{
		BaseOpenTelemetry: BaseOpenTelemetry{
			Enabled: true,
			ExporterConfig: ExporterConfig{
				Exporter:     "http",
				Endpoint:     "collector:4318",
				ResourceName: "root-gw",
			},
		},
	}
	cfg.SetDefaults()
	assert.True(t, cfg.TracesEnabled())
	assert.Same(t, &cfg.BaseOpenTelemetry, cfg.EffectiveTraceConfig())
	assert.Equal(t, "http", cfg.Metrics.Exporter)
	assert.Equal(t, "collector:4318", cfg.Metrics.Endpoint)
	assert.Equal(t, "root-gw", cfg.Metrics.ResourceName)

	runtimeMetricCases := []struct {
		name string
		cfg  *MetricsConfig
		want bool
	}{
		{
			name: "metrics enabled defaults runtime metrics to true",
			cfg: &MetricsConfig{
				BaseMetricsConfig: BaseMetricsConfig{Enabled: boolPtr(true)},
			},
			want: true,
		},
		{
			name: "explicit runtime metrics false disables runtime metrics",
			cfg: &MetricsConfig{
				BaseMetricsConfig: BaseMetricsConfig{Enabled: boolPtr(true)},
				RuntimeMetrics:    boolPtr(false),
			},
			want: false,
		},
		{
			name: "metrics disabled disables runtime metrics",
			cfg: &MetricsConfig{
				BaseMetricsConfig: BaseMetricsConfig{Enabled: boolPtr(false)},
				RuntimeMetrics:    boolPtr(true),
			},
			want: false,
		},
	}

	for _, tt := range runtimeMetricCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRuntimeMetricsEnabled(tt.cfg))
		})
	}

	inst, tp := activeProvider(t)
	require.NotNil(t, inst.provider)
	require.NotNil(t, inst.requestCounter)
	require.NotNil(t, inst.apisLoaded)
	require.NotNil(t, inst.policiesLoaded)
	require.NotNil(t, inst.reloadCounter)
	require.NotNil(t, inst.reloadDuration)

	ctx := context.Background()
	inst.RecordRequest(ctx)
	inst.RecordConfigState(ctx, 7, 3)
	inst.RecordReload(ctx, 250*time.Millisecond)

	metrictest.AssertSum(t, tp.FindMetric(t, "tyk.http.requests"), int64(1))
	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.apis.loaded"), float64(7))
	metrictest.AssertGauge(t, tp.FindMetric(t, "tyk.gateway.policies.loaded"), float64(3))
	metrictest.AssertSum(t, tp.FindMetric(t, "tyk.gateway.config.reload"), int64(1))
	metrictest.AssertHistogramSum(t, tp.FindMetric(t, "tyk.gateway.config.reload.duration"), 0.25)

	inst.SetRegistry(tp, []apimetrics.APIMetricDefinition{
		{
			Name: "proof.runtime.api",
			Type: "counter",
			Dimensions: []apimetrics.DimensionDefinition{
				{Source: "session", Key: "api_key", Label: "token"},
				{Source: "context", Key: "tier", Label: "tier", Default: "standard"},
				{Source: "response_header", Key: "X-Version", Label: "version", Default: "unknown"},
				{Source: "config_data", Key: "env", Label: "env", Default: "dev"},
				{Source: "metadata", Key: "mcp_method", Label: "mcp.method", Default: "none"},
			},
		},
	})
	assert.True(t, inst.NeedsSession())
	assert.True(t, inst.NeedsContext())
	assert.True(t, inst.NeedsResponse())
	assert.True(t, inst.NeedsConfigData())
	assert.True(t, inst.NeedsMCP())

	response := &http.Response{Header: http.Header{}}
	response.Header.Set("X-Version", "v1")
	inst.RecordAPIMetrics(ctx, &apimetrics.RequestContext{
		Request:          httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		Response:         response,
		StatusCode:       200,
		Token:            "abcdefghijklmnop",
		ContextVariables: map[string]interface{}{"tier": "gold"},
		ConfigData:       map[string]interface{}{"env": "prod"},
		MCPMethod:        "tools/list",
	})
	metrictest.AssertSum(t, tp.FindMetric(t, "proof.runtime.api"), int64(1))

	badInst, badTP := activeProvider(t)
	assert.Panics(t, func() {
		badInst.SetRegistry(badTP, []apimetrics.APIMetricDefinition{{Name: "", Type: "counter"}})
	})

	disabledTrace := InitOpenTelemetry(ctx, logrus.New(), &OpenTelemetry{
		BaseOpenTelemetry: BaseOpenTelemetry{Enabled: false},
	}, "gw-disabled", "v0", false, "", false, nil)
	assert.Equal(t, tyktrace.NOOP_PROVIDER, disabledTrace.Type())

	apiAttrs := ApidefSpanAttributes(&apidef.APIDefinition{
		APIID:        "api-id",
		OrgID:        "org-id",
		Name:         "api-name",
		Proxy:        apidef.ProxyConfig{ListenPath: "/api"},
		TagsDisabled: true,
	})
	assert.ElementsMatch(t, []SpanAttribute{
		tyktrace.NewAttribute(string(semconv.TykAPINameKey), "api-name"),
		tyktrace.NewAttribute(string(semconv.TykAPIOrgIDKey), "org-id"),
		tyktrace.NewAttribute(string(semconv.TykAPIIDKey), "api-id"),
		tyktrace.NewAttribute(string(semconv.TykAPIListenPathKey), "/api"),
	}, apiAttrs)
	assert.Equal(t, tyktrace.NewAttribute(string(semconv.TykAPIVersionKey), NON_VERSIONED), APIVersionAttribute(""))
	assert.Equal(t, []SpanAttribute{
		tyktrace.NewAttribute(string(semconv.TykGWIDKey), "gw-id"),
		tyktrace.NewAttribute(string(semconv.TykGWDataplaneKey), true),
		tyktrace.NewAttribute(string(semconv.TykDataplaneGWGroupIDKey), "group-a"),
		tyktrace.NewAttribute(string(semconv.TykGWSegmentTagsKey), []string{"edge"}),
	}, GatewayResourceAttributes("gw-id", true, "group-a", true, []string{"edge"}))

	traceProvider := makeProviderHTTP(t)
	spanCtx, span := traceProvider.Tracer().Start(ctx, "reqproof-runtime")
	defer span.End()
	spanCtx = ContextWithSpan(spanCtx, span)

	traceID, spanID := ExtractTraceAndSpanID(spanCtx)
	require.NotEmpty(t, traceID)
	require.NotEmpty(t, spanID)
	assert.Equal(t, traceID, ExtractTraceID(spanCtx))
	assert.Equal(t, span, SpanFromContext(spanCtx))

	rr := httptest.NewRecorder()
	AddTraceID(spanCtx, rr)
	assert.Equal(t, traceID, rr.Header().Get(TykTraceIDHeader))
}
