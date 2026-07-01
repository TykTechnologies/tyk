package apimetrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

// Verifies: STK-REQ-092, SYS-REQ-180, SW-REQ-167
// SW-REQ-167:nominal:nominal
// SW-REQ-167:boundary:nominal
// SW-REQ-167:error_handling:nominal
// SW-REQ-167:encoding_safety:nominal
// SW-REQ-167:determinism:nominal
// SYS-REQ-180:determinism:nominal
// MCDC SYS-REQ-180: api_metrics_config_decode_determined=T, api_metrics_default_definitions_determined=T, api_metrics_definition_validation_determined=T, api_metrics_dimension_builder_reuse_determined=T, api_metrics_dimension_extraction_determined=T, api_metrics_filter_matching_determined=T, api_metrics_local_recording_determined=T, api_metrics_registry_flags_determined=T => TRUE
// MCDC SW-REQ-167: api_metrics_config_decode_determined=T, api_metrics_default_definitions_determined=T, api_metrics_definition_validation_determined=T, api_metrics_dimension_builder_reuse_determined=T, api_metrics_dimension_extraction_determined=T, api_metrics_filter_matching_determined=T, api_metrics_local_recording_determined=T, api_metrics_registry_flags_determined=T => TRUE
func TestAPIMetricsLocalBehaviorReqProof(t *testing.T) {
	var decoded APIMetricDefinitions
	err := decoded.Decode(`[{"name":"proof.decoded","type":"counter","dimensions":[{"source":"metadata","key":"method","label":"method"}],"filters":{"api_ids":["api-1"],"methods":["GET"],"status_codes":["2xx"]}}]`)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "proof.decoded", decoded[0].Name)

	defaults := DefaultAPIMetrics()
	require.Len(t, defaults, 4)
	assert.Equal(t, "http.server.request.duration", defaults[0].Name)

	warnings, err := ValidateDefinitions([]APIMetricDefinition{
		{
			Name: "proof.valid.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method"},
			},
		},
		{
			Name:            "proof.valid.histogram",
			Type:            "histogram",
			HistogramSource: "total",
			Dimensions: []DimensionDefinition{
				{Source: "session", Key: "api_key"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{`api_metrics["proof.valid.histogram"]: session dimension "api_key" on histogram has high cardinality risk`}, warnings)

	builder, err := NewDimensionBuilder([]DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "method"},
		{Source: "header", Key: "X-Missing", Label: "missing", Default: "fallback"},
		{Source: "session", Key: "api_key", Label: "key"},
	})
	require.NoError(t, err)

	dimensionCases := []struct {
		name string
		rc   *RequestContext
		want []attribute.KeyValue
	}{
		{
			name: "first build extracts metadata default and truncated token",
			rc: &RequestContext{
				Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil),
				Token:   "abcdefghijklmnop",
			},
			want: []attribute.KeyValue{
				attribute.String("method", "POST"),
				attribute.String("missing", "fallback"),
				attribute.String("key", "klmnop"),
			},
		},
		{
			name: "second build reuses builder without retaining previous values",
			rc: &RequestContext{
				Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
				Token:   "short",
			},
			want: []attribute.KeyValue{
				attribute.String("method", "GET"),
				attribute.String("missing", "fallback"),
				attribute.String("key", "short"),
			},
		},
	}

	for _, tt := range dimensionCases {
		t.Run(tt.name, func(t *testing.T) {
			ref, got := builder.Build(tt.rc)
			defer builder.Release(ref)
			assert.Equal(t, tt.want, got)
		})
	}

	filter := CompileFilter(&MetricFilters{
		APIIDs:      []string{"api-1"},
		Methods:     []string{"get"},
		StatusCodes: []string{"2xx"},
	})
	filterCases := []struct {
		name       string
		apiID      string
		method     string
		statusCode int
		want       bool
	}{
		{name: "all dimensions match", apiID: "api-1", method: http.MethodGet, statusCode: 201, want: true},
		{name: "api id mismatch", apiID: "api-2", method: http.MethodGet, statusCode: 201, want: false},
		{name: "method mismatch", apiID: "api-1", method: http.MethodPost, statusCode: 201, want: false},
		{name: "status class mismatch", apiID: "api-1", method: http.MethodGet, statusCode: 500, want: false},
	}

	for _, tt := range filterCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, filter.Match(tt.apiID, tt.method, tt.statusCode))
		})
	}

	reg, tp := makeRealRegistry(t, []APIMetricDefinition{
		{
			Name: "proof.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "method"},
				{Source: "session", Key: "api_key", Label: "token"},
				{Source: "context", Key: "tier", Label: "tier", Default: "standard"},
				{Source: "response_header", Key: "X-Trace", Label: "trace", Default: "none"},
			},
			Filters: &MetricFilters{
				APIIDs:      []string{"api-1"},
				Methods:     []string{"GET"},
				StatusCodes: []string{"2xx"},
			},
		},
		{
			Name:            "proof.latency",
			Type:            "histogram",
			HistogramSource: "total",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "mcp_method", Label: "mcp.method", Default: "none"},
				{Source: "config_data", Key: "env", Label: "env", Default: "dev"},
			},
		},
	})
	assert.True(t, reg.NeedsSession())
	assert.True(t, reg.NeedsContext())
	assert.True(t, reg.NeedsResponse())
	assert.True(t, reg.NeedsMCP())
	assert.True(t, reg.NeedsConfigData())

	response := &http.Response{Header: http.Header{}}
	response.Header.Set("X-Trace", "trace-42")

	reg.RecordAPIMetrics(context.Background(), &RequestContext{
		Request:          httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		Response:         response,
		StatusCode:       201,
		APIID:            "api-1",
		Token:            "abcdefghijklmnop",
		ContextVariables: map[string]interface{}{"tier": "gold"},
		MCPMethod:        "tools/call",
		ConfigData:       map[string]interface{}{"env": "prod"},
		LatencyTotal:     250,
	})

	assertMetrics(t, tp, []metricAssertion{
		{
			Name: "proof.counter",
			Type: "counter",
			Sum:  1,
			Attrs: map[string]string{
				"method": "GET",
				"token":  "klmnop",
				"tier":   "gold",
				"trace":  "trace-42",
			},
		},
		{
			Name:      "proof.latency",
			Type:      "histogram",
			HistCount: 1,
			HistSum:   0.25,
			Attrs: map[string]string{
				"mcp.method": "tools/call",
				"env":        "prod",
			},
		},
	})
}
