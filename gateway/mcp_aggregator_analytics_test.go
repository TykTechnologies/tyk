package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otelglobal "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// analyticsRecords collects every analytics record the gateway writes.
type analyticsRecords struct {
	mu      sync.Mutex
	records []analytics.AnalyticsRecord
}

func collectAnalytics(ts *Test) *analyticsRecords {
	collected := &analyticsRecords{}
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		collected.mu.Lock()
		defer collected.mu.Unlock()
		collected.records = append(collected.records, *record)
	}
	return collected
}

func (c *analyticsRecords) forAPI(apiID string) []analytics.AnalyticsRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []analytics.AnalyticsRecord
	for _, record := range c.records {
		if record.APIID == apiID {
			out = append(out, record)
		}
	}
	return out
}

func (c *analyticsRecords) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = nil
}

func (c *analyticsRecords) withAggregatorOrigin() []analytics.AnalyticsRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []analytics.AnalyticsRecord
	for _, record := range c.records {
		if record.MCPStats.AggregatorAPIID != "" || hasAggregatorTag(record.Tags) {
			out = append(out, record)
		}
	}
	return out
}

func hasAggregatorTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, mcpAggregatorAnalyticsTagPrefix) {
			return true
		}
	}
	return false
}

func singleRecord(t *testing.T, records []analytics.AnalyticsRecord, apiID string) analytics.AnalyticsRecord {
	t.Helper()
	require.Len(t, records, 1, "expected one analytics record for %s", apiID)
	return records[0]
}

// startMCPAggregatorAnalyticsTest loads orders-rest, the API-to-MCP proxy
// orders-mcp over it, the remote MCP proxy github-mcp and the aggregator
// company-tools over both proxies.
func startMCPAggregatorAnalyticsTest(t *testing.T, conf func(*config.Config), orders func(*APISpec)) (*Test, *analyticsRecords) {
	t.Helper()
	ts := StartTest(conf)
	t.Cleanup(ts.Close)
	ordersBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(ordersBackend.Close)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	github.call = answering(`{"content":[{"type":"text","text":"0 issues"}]}`)

	// As /tyk/mcps saves it: an API-to-MCP proxy is MCP-managed, not marked MCP.
	ordersSpec := ordersMCPProxyRuntimeSpec()
	require.False(t, ordersSpec.IsMCP())
	require.True(t, ordersSpec.IsPairedMCPAdapterProxy())
	if orders != nil {
		orders(ordersSpec)
	}
	specs := []*APISpec{
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersSpec,
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	}
	for _, spec := range specs {
		spec.DoNotTrack = false
	}
	ts.Gw.LoadAPI(specs...)
	return ts, collectAnalytics(ts)
}

func tracesOn(collectorURL string) func(*config.Config) {
	return func(c *config.Config) {
		c.OpenTelemetry.Enabled = true
		c.OpenTelemetry.Exporter = "http"
		c.OpenTelemetry.Endpoint = collectorURL
		c.OpenTelemetry.SpanProcessorType = "simple"
	}
}

func ordersMCPKey(t *testing.T, ts *Test) string {
	t.Helper()
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{
			"orders-mcp": {APIID: "orders-mcp", APIName: "orders-mcp"},
		}
	})
	require.NotEmpty(t, key)
	return key
}

func TestMCPAggregatorRecordsTheNamespacedToolCallWithoutAnOrigin(t *testing.T) {
	ts, records := startMCPAggregatorAnalyticsTest(t, nil, nil)

	res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("orders__list_orders", `{}`, ""))
	require.Equal(t, http.StatusOK, res.status, res.body)
	require.Nil(t, res.rpc.Error, res.body)

	agg := singleRecord(t, records.forAPI("company-tools"), "company-tools")
	assert.True(t, agg.MCPStats.IsMCP)
	assert.Equal(t, mcp.MethodToolsCall, agg.MCPStats.JSONRPCMethod)
	assert.Equal(t, "tool", agg.MCPStats.PrimitiveType)
	assert.Equal(t, "orders__list_orders", agg.MCPStats.PrimitiveName)
	assert.Empty(t, agg.MCPStats.AggregatorAPIID, "the aggregator's own record has no aggregator origin")
	assert.False(t, hasAggregatorTag(agg.Tags), agg.Tags)
}

func TestMCPAggregatorMarksTheRoutedProxyRecordWithItsOrigin(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(collector.Close)
	for _, traces := range []bool{false, true} {
		t.Run(map[bool]string{false: "traces off", true: "traces on"}[traces], func(t *testing.T) {
			var conf func(*config.Config)
			if traces {
				conf = tracesOn(collector.URL)
			}
			ts, records := startMCPAggregatorAnalyticsTest(t, conf, nil)
			require.Equal(t, traces, ts.Gw.GetConfig().OpenTelemetry.TracesEnabled())

			res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("orders__list_orders", `{}`, ""))
			require.Equal(t, http.StatusOK, res.status, res.body)
			require.Nil(t, res.rpc.Error, res.body)

			orders := singleRecord(t, records.forAPI("orders-mcp"), "orders-mcp")
			assert.True(t, orders.MCPStats.IsMCP)
			assert.Equal(t, mcp.MethodToolsCall, orders.MCPStats.JSONRPCMethod)
			assert.Equal(t, "list_orders", orders.MCPStats.PrimitiveName)
			assert.Equal(t, "company-tools", orders.MCPStats.AggregatorAPIID)
			assert.Contains(t, orders.Tags, "mcp-aggregator-company-tools")

			for _, marked := range records.withAggregatorOrigin() {
				assert.Equal(t, "orders-mcp", marked.APIID, "only the routed proxy's record carries the origin")
			}
		})
	}
}

func TestMCPAggregatorMarksTheRoutedProxyErrorRecordWithItsOrigin(t *testing.T) {
	const blockedIP = "203.0.113.9"
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(collector.Close)
	for _, traces := range []bool{false, true} {
		t.Run(map[bool]string{false: "traces off", true: "traces on"}[traces], func(t *testing.T) {
			var conf func(*config.Config)
			if traces {
				conf = tracesOn(collector.URL)
			}
			ts, records := startMCPAggregatorAnalyticsTest(t, conf, func(orders *APISpec) {
				orders.EnableIpBlacklisting = true
				orders.BlacklistedIPs = []string{blockedIP}
			})

			res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("orders__list_orders", `{}`, ""), "X-Real-IP", blockedIP)
			require.Equal(t, http.StatusOK, res.status, res.body)
			require.NotNil(t, res.rpc.Error, res.body)

			orders := singleRecord(t, records.forAPI("orders-mcp"), "orders-mcp")
			assert.Equal(t, http.StatusForbidden, orders.ResponseCode)
			assert.Equal(t, "company-tools", orders.MCPStats.AggregatorAPIID)
			assert.Contains(t, orders.Tags, "mcp-aggregator-company-tools")
		})
	}
}

func TestMCPProxyDirectCallHasNoAggregatorOrigin(t *testing.T) {
	spoofed := map[string][]string{
		"no extra headers": nil,
		"look-alike aggregator headers": {
			"X-Tyk-MCP-Aggregator", "company-tools",
			"X-Tyk-MCP-Aggregator-API-ID", "company-tools",
			"X-Tyk-Aggregator-API-ID", "company-tools",
			"Mcp-Aggregator", "company-tools",
			"X-Tyk-Mcp-Upstream-Api-Id", "orders-mcp",
		},
	}
	for name, extra := range spoofed {
		t.Run(name, func(t *testing.T) {
			ts, records := startMCPAggregatorAnalyticsTest(t, nil, nil)

			res := postMCPToolsCallTo(t, ts, "/orders-mcp/", ordersMCPKey(t, ts), toolCallParams("list_orders", `{}`, ""), extra...)
			require.Equal(t, http.StatusOK, res.status, res.body)
			require.Nil(t, res.rpc.Error, res.body)

			orders := singleRecord(t, records.forAPI("orders-mcp"), "orders-mcp")
			assert.True(t, orders.MCPStats.IsMCP)
			assert.Equal(t, mcp.MethodToolsCall, orders.MCPStats.JSONRPCMethod)
			assert.Equal(t, "list_orders", orders.MCPStats.PrimitiveName)
			assert.Empty(t, orders.MCPStats.AggregatorAPIID)
			assert.Empty(t, records.withAggregatorOrigin())
		})
	}
}

func TestMCPAggregatorMarksToolsListFanOutRecordsWithItsOrigin(t *testing.T) {
	ts, records := startMCPAggregatorAnalyticsTest(t, nil, nil)
	key := companyToolsKey(t, ts)
	// The first call may also run the admission probes; only the second is
	// a plain catalogue fan-out.
	require.Equal(t, http.StatusOK, postModernToolsList(t, ts, "/company-tools/", key).status)
	records.reset()

	res := postModernToolsList(t, ts, "/company-tools/", key)
	require.Equal(t, http.StatusOK, res.status, res.body)
	require.Contains(t, res.tools, "orders__list_orders")
	require.Contains(t, res.tools, "github__list_issues")

	agg := singleRecord(t, records.forAPI("company-tools"), "company-tools")
	assert.Equal(t, mcp.MethodToolsList, agg.MCPStats.JSONRPCMethod)
	assert.Empty(t, agg.MCPStats.AggregatorAPIID)

	for _, apiID := range []string{"orders-mcp", "github-mcp"} {
		source := records.forAPI(apiID)
		require.NotEmpty(t, source, apiID)
		for _, record := range source {
			assert.Equal(t, mcp.MethodToolsList, record.MCPStats.JSONRPCMethod, apiID)
			assert.Equal(t, "company-tools", record.MCPStats.AggregatorAPIID, apiID)
			assert.Contains(t, record.Tags, "mcp-aggregator-company-tools", apiID)
		}
	}
}

// recordingTracerProvider is a gateway tracer provider over an SDK provider
// whose spans are kept in memory.
type recordingTracerProvider struct {
	*sdktrace.TracerProvider
}

func (p recordingTracerProvider) Tracer() oteltrace.Tracer {
	return p.TracerProvider.Tracer("tyk-test")
}
func (p recordingTracerProvider) Type() string { return "otel" }
func (p recordingTracerProvider) Shutdown(ctx context.Context) error {
	return p.TracerProvider.Shutdown(ctx)
}

func installSpanRecorder(t *testing.T, ts *Test) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previousProvider, previousPropagator := otelglobal.GetTracerProvider(), otelglobal.GetTextMapPropagator()
	otelglobal.SetTracerProvider(provider)
	otelglobal.SetTextMapPropagator(propagation.TraceContext{})
	ts.Gw.TracerProvider = recordingTracerProvider{provider}
	t.Cleanup(func() {
		otelglobal.SetTracerProvider(previousProvider)
		otelglobal.SetTextMapPropagator(previousPropagator)
		_ = provider.Shutdown(context.Background())
	})
	return recorder
}

func spanAPIID(span sdktrace.ReadOnlySpan) string {
	for _, attr := range span.Attributes() {
		if attr.Key == "tyk.api.id" {
			return attr.Value.AsString()
		}
	}
	return ""
}

// apiEntrySpan returns the outermost span of an API's chain: the API's span
// whose parent is not one of that API's own spans (its VEM hops nest inside it).
func apiEntrySpan(spans []sdktrace.ReadOnlySpan, apiID string) (entry, parent sdktrace.ReadOnlySpan) {
	byID := make(map[oteltrace.SpanID]sdktrace.ReadOnlySpan, len(spans))
	for _, span := range spans {
		byID[span.SpanContext().SpanID()] = span
	}
	for _, span := range spans {
		if spanAPIID(span) != apiID {
			continue
		}
		p := byID[span.Parent().SpanID()]
		if p == nil || spanAPIID(p) != apiID {
			return span, p
		}
	}
	return nil, nil
}

func TestMCPAggregatorTraceHasTheRoutedProxySpanAsAChildOfTheAggregatorSpan(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(collector.Close)
	ts := StartTest(tracesOn(collector.URL))
	t.Cleanup(ts.Close)
	recorder := installSpanRecorder(t, ts)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	github.call = answering(`{"content":[{"type":"text","text":"0 issues"}]}`)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)

	res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("github__list_issues", `{}`, ""))
	require.Equal(t, http.StatusOK, res.status, res.body)
	require.Nil(t, res.rpc.Error, res.body)

	spans := recorder.Ended()
	agg, aggParent := apiEntrySpan(spans, "company-tools")
	require.NotNil(t, agg, "aggregator span")
	assert.Nil(t, aggParent, "the aggregator span is the root of the trace")
	assert.False(t, agg.Parent().IsValid())
	source, sourceParent := apiEntrySpan(spans, "github-mcp")
	require.NotNil(t, source, "github-mcp span")
	require.NotNil(t, sourceParent, "the github-mcp span has a parent span in the trace")
	assert.Equal(t, "company-tools", spanAPIID(sourceParent), "the github-mcp span is a child of the aggregator's span")
	for _, span := range spans {
		assert.Equal(t, agg.SpanContext().TraceID(), span.SpanContext().TraceID(), "span %q is in the aggregator's trace", span.Name())
	}
}
