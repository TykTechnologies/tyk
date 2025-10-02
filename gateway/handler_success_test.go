package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/httpclient"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	ctxpkg "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

type bindContextFunc = func(context.Context) context.Context
type bindAPIDefFunc = func(*APISpec)

func testRequestWithContext(binding bindContextFunc) *http.Request {
	req, _ := http.NewRequest("GET", "/", nil)
	ctx := req.Context()
	if binding != nil {
		ctx = binding(ctx)
	}
	return req.WithContext(ctx)
}

func testAPISpec(binding bindAPIDefFunc) *APISpec {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
		GlobalConfig:  config.Config{},
	}
	if binding != nil {
		binding(spec)
	}
	return spec
}

func TestRecordDetail(t *testing.T) {
	testcases := []struct {
		title   string
		spec    *APISpec
		binding bindContextFunc
		expect  bool
	}{
		{
			title:  "empty session",
			spec:   testAPISpec(nil),
			expect: false,
		},
		{
			title: "empty session, enabled analytics",
			spec: testAPISpec(func(spec *APISpec) {
				spec.EnableDetailedRecording = true
			}),
			expect: true,
		},
		{
			title: "empty session, enabled config",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = false
				spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording = true
			}),
			expect: true,
		},
		{
			title: "normal session",
			spec:  testAPISpec(nil),
			// attach user session
			binding: func(ctx context.Context) context.Context {
				session := &user.SessionState{
					EnableDetailedRecording: true,
				}
				return context.WithValue(ctx, ctxpkg.SessionData, session)
			},
			expect: true,
		},
		{
			title: "org empty session",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = true
			}),
			expect: false,
		},
		{
			title: "org session",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = true
			}),
			// attach user session
			binding: func(ctx context.Context) context.Context {
				session := &user.SessionState{
					EnableDetailedRecording: true,
				}
				return context.WithValue(ctx, ctxpkg.OrgSessionContext, session)
			},
			expect: true,
		},
		{
			title: "graphql request",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GraphQL.Enabled = true
			}),
			expect: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			req := testRequestWithContext(tc.binding)
			got := recordDetail(req, tc.spec)
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestAnalyticRecord_GraphStats(t *testing.T) {

	generateApiDefinition := func(spec *APISpec) {
		spec.Name = "graphql API"
		spec.APIID = "graphql-api"
		spec.Proxy.TargetURL = testGraphQLProxyUpstream
		spec.Proxy.ListenPath = "/"
		spec.GraphQL = apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			Version:       apidef.GraphQLConfigVersion2,
			Schema:        gqlProxyUpstreamSchema,
		}
	}

	testCases := []struct {
		name      string
		code      int
		request   graphql.Request
		checkFunc func(*testing.T, *analytics.AnalyticsRecord)
		reloadAPI func(*APISpec)
		headers   map[string]string
	}{
		{
			name: "successfully generate stats",
			code: http.StatusOK,
			request: graphql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			},
			checkFunc: func(t *testing.T, record *analytics.AnalyticsRecord) {
				t.Helper()
				assert.True(t, record.GraphQLStats.IsGraphQL)
				assert.False(t, record.GraphQLStats.HasErrors)
				assert.ElementsMatch(t, []string{"hello", "httpMethod"}, record.GraphQLStats.RootFields)
				assert.Equal(t, map[string][]string{}, record.GraphQLStats.Types)
				assert.Equal(t, analytics.OperationQuery, record.GraphQLStats.OperationType)
			},
		},
		{
			name: "should have variables",
			code: http.StatusOK,
			request: graphql.Request{
				Query:     `{ hello(name: "World") httpMethod }`,
				Variables: []byte(`{"in":"hello"}`),
			},
			checkFunc: func(t *testing.T, record *analytics.AnalyticsRecord) {
				t.Helper()
				assert.True(t, record.GraphQLStats.IsGraphQL)
				assert.False(t, record.GraphQLStats.HasErrors)
				assert.ElementsMatch(t, []string{"httpMethod", "hello"}, record.GraphQLStats.RootFields)
				assert.Equal(t, map[string][]string{}, record.GraphQLStats.Types)
				assert.Equal(t, analytics.OperationQuery, record.GraphQLStats.OperationType)
				assert.Equal(t, `{"in":"hello"}`, record.GraphQLStats.Variables)
			},
		},
		{
			name: "should read response and error response request with detailed recording",
			code: http.StatusInternalServerError,
			request: graphql.Request{
				Query:     `{ hello(name: "World") httpMethod }`,
				Variables: []byte(`{"in":"hello"}`),
			},
			reloadAPI: func(spec *APISpec) {
				spec.Proxy.TargetURL = testGraphQLProxyUpstreamError
				spec.EnableDetailedRecording = true
			},
			checkFunc: func(t *testing.T, record *analytics.AnalyticsRecord) {
				t.Helper()
				assert.True(t, record.GraphQLStats.IsGraphQL)
				assert.True(t, record.GraphQLStats.HasErrors)
				assert.ElementsMatch(t, []string{"hello", "httpMethod"}, record.GraphQLStats.RootFields)
				assert.Equal(t, map[string][]string{}, record.GraphQLStats.Types)
				assert.Equal(t, analytics.OperationQuery, record.GraphQLStats.OperationType)
				assert.Equal(t, `{"in":"hello"}`, record.GraphQLStats.Variables)
				assert.Equal(t, []analytics.GraphError{
					{Message: "unable to resolve"},
				}, record.GraphQLStats.Errors)
			},
		},
		{
			name: "should read response request without detailed recording",
			code: http.StatusInternalServerError,
			request: graphql.Request{
				Query:     `{ hello(name: "World") httpMethod }`,
				Variables: []byte(`{"in":"hello"}`),
			},
			reloadAPI: func(spec *APISpec) {
				spec.Proxy.TargetURL = testGraphQLProxyUpstreamError
			},
			checkFunc: func(t *testing.T, record *analytics.AnalyticsRecord) {
				t.Helper()
				assert.True(t, record.GraphQLStats.IsGraphQL)
				assert.True(t, record.GraphQLStats.HasErrors)
				assert.ElementsMatch(t, []string{"hello", "httpMethod"}, record.GraphQLStats.RootFields)
				assert.Equal(t, map[string][]string{}, record.GraphQLStats.Types)
				assert.Equal(t, analytics.OperationQuery, record.GraphQLStats.OperationType)
				assert.Equal(t, `{"in":"hello"}`, record.GraphQLStats.Variables)
				assert.Equal(t, []analytics.GraphError{
					{Message: "unable to resolve"},
				}, record.GraphQLStats.Errors)
			},
		},
		{
			name: "successfully generate stats for compressed request body",
			code: http.StatusOK,
			request: graphql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			},
			headers: map[string]string{
				httpclient.AcceptEncodingHeader: "gzip",
			},
			checkFunc: func(t *testing.T, record *analytics.AnalyticsRecord) {
				t.Helper()
				assert.True(t, record.GraphQLStats.IsGraphQL)
				assert.False(t, record.GraphQLStats.HasErrors)
				assert.ElementsMatch(t, []string{"hello", "httpMethod"}, record.GraphQLStats.RootFields)
				assert.Equal(t, map[string][]string{}, record.GraphQLStats.Types)
				assert.Equal(t, analytics.OperationQuery, record.GraphQLStats.OperationType)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec := BuildAPI(generateApiDefinition)[0]
			if tc.reloadAPI != nil {
				tc.reloadAPI(spec)
			}

			ts := StartTest(nil)
			defer ts.Close()
			ts.Gw.LoadAPI(spec)
			ts.Gw.Analytics.mockEnabled = true
			ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
				tc.checkFunc(t, record)
			}
			var headers = map[string]string{
				httpclient.AcceptEncodingHeader: "",
			}
			if tc.headers != nil {
				headers = tc.headers
			}
			_, err := ts.Run(t, test.TestCase{
				Data:    tc.request,
				Method:  http.MethodPost,
				Code:    tc.code,
				Headers: headers,
			})
			assert.NoError(t, err)
		})
	}
}

func TestAnalyticsIgnoreSubgraph(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	accountsSubgraph := BuildAPI(func(spec *APISpec) {
		spec.Name = "subgraph-accounts"
		spec.APIID = "subgraph-accounts"
		spec.Proxy.TargetURL = testSubgraphAccounts
		spec.Proxy.ListenPath = "/subgraph-accounts"
		spec.GraphQL = apidef.GraphQLConfig{
			Enabled: true,

			ExecutionMode: apidef.GraphQLExecutionModeSubgraph,
			Version:       apidef.GraphQLConfigVersion2,
			Schema:        gqlSubgraphSchemaAccounts,
			Subgraph: apidef.GraphQLSubgraphConfig{
				SDL: gqlSubgraphSDLAccounts,
			},
		}
	})[0]

	superGraph := BuildAPI(func(spec *APISpec) {
		spec.Name = "supergraph"
		spec.APIID = "supergraph"
		spec.Proxy.ListenPath = "/supergraph"
		spec.EnableDetailedRecording = true
		spec.GraphQL = apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeSupergraph,
			Version:       apidef.GraphQLConfigVersion2,
			Supergraph: apidef.GraphQLSupergraphConfig{
				Subgraphs: []apidef.GraphQLSubgraphEntity{
					{
						Name:  "subgraph-accounts",
						APIID: "subgraph-accounts",
						SDL:   gqlSubgraphSDLAccounts,
						URL:   "tyk://subgraph-accounts",
					},
				},
				MergedSDL: gqlMergedSupergraphSDL,
			},
			Schema: gqlMergedSupergraphSDL,
		}
	})[0]

	ts.Gw.LoadAPI(accountsSubgraph, superGraph)

	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		if record.APIID != "subgraph-accounts" {
			return
		}
		found := false
		for _, val := range record.Tags {
			if val == "tyk-graph-analytics" {
				found = true
				break
			}
		}
		if record.ApiSchema != "" && found {
			t.Error("subgraph request should not tagged or have schema")
		}
		assert.False(t, record.GraphQLStats.IsGraphQL)
	}

	_, err := ts.Run(t,
		test.TestCase{
			Path: "/supergraph",
			Data: graphql.Request{
				Query: `query Query { me { id username} }`,
			},
			Code: 200,
		},
		test.TestCase{
			Path: "/supergraph",
			Data: graphql.Request{
				Query: `query Query { mem { id username} }`,
			},
			Code: 400,
		},
	)
	assert.NoError(t, err)
}

func TestSuccessHandler_RecordHit_TraceID(t *testing.T) {
	testCases := []struct {
		name                 string
		openTelemetryEnabled bool
		setupContext         func(context.Context) context.Context
		expectedTraceID      string
		description          string
	}{
		{
			name:                 "should populate TraceID when OpenTelemetry is enabled and valid trace exists",
			openTelemetryEnabled: true,
			setupContext: func(ctx context.Context) context.Context {
				traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
				spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
				spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
				})
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:                 "should not populate TraceID when OpenTelemetry is disabled",
			openTelemetryEnabled: false,
			setupContext: func(ctx context.Context) context.Context {
				traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
				spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
				spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
				})
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "",
		},
		{
			name:                 "should not populate TraceID when no valid span context exists",
			openTelemetryEnabled: true,
			setupContext: func(ctx context.Context) context.Context {
				return ctx
			},
			expectedTraceID: "",
		},
		{
			name:                 "should not populate TraceID when span context is invalid",
			openTelemetryEnabled: true,
			setupContext: func(ctx context.Context) context.Context {
				spanCtx := trace.SpanContext{}
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			globalConf := ts.Gw.GetConfig()
			globalConf.OpenTelemetry.Enabled = tc.openTelemetryEnabled
			globalConf.EnableAnalytics = true

			spec := BuildAPI(func(spec *APISpec) {
				spec.Name = "test-api"
				spec.APIID = "test-api-id"
				spec.Proxy.ListenPath = "/test"
				spec.GlobalConfig.OpenTelemetry.Enabled = tc.openTelemetryEnabled
				spec.GlobalConfig.EnableAnalytics = true
				spec.DoNotTrack = false
			})[0]

			ts.Gw.LoadAPI(spec)

			var capturedRecord *analytics.AnalyticsRecord
			ts.Gw.Analytics.mockEnabled = true
			ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
				capturedRecord = record
			}

			req, _ := http.NewRequest("GET", "/test", nil)
			ctx := req.Context()
			if tc.setupContext != nil {
				ctx = tc.setupContext(ctx)
			}
			req = req.WithContext(ctx)

			successHandler := &SuccessHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
					Gw:   ts.Gw,
				},
			}

			// Create a mock response to avoid nil pointer dereference
			mockResponse := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       http.NoBody,
			}

			successHandler.RecordHit(req, analytics.Latency{Total: 100}, 200, mockResponse, false)

			if capturedRecord == nil {
				t.Fatal("Analytics record should be captured but was nil")
			}

			assert.Equal(t, tc.expectedTraceID, capturedRecord.TraceID, tc.description)

			assert.Equal(t, "GET", capturedRecord.Method, "Method should be captured correctly")
			assert.Equal(t, "/test", capturedRecord.Path, "Path should be captured correctly")
			assert.Equal(t, 200, capturedRecord.ResponseCode, "Response code should be captured correctly")
		})
	}
}

func TestSuccessHandler_TraceIDResponseHeader(t *testing.T) {
	testCases := []struct {
		name                 string
		openTelemetryEnabled bool
		detailedRecording    bool
		setupContext         func(context.Context) context.Context
		expectedTraceID      string
		expectHeader         bool
		description          string
	}{
		{
			name:                 "should add X-Tyk-Trace-Id header when OpenTelemetry is enabled and valid trace exists",
			openTelemetryEnabled: true,
			detailedRecording:    true,
			setupContext: func(ctx context.Context) context.Context {
				traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
				spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
				spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
				})
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			expectHeader:    true,
			description:     "Valid trace ID should be added as response header",
		},
		{
			name:                 "should not add X-Tyk-Trace-Id header when OpenTelemetry is disabled",
			openTelemetryEnabled: false,
			detailedRecording:    true,
			setupContext: func(ctx context.Context) context.Context {
				traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
				spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
				spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
				})
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "",
			expectHeader:    false,
		},
		{
			name:                 "should not add X-Tyk-Trace-Id header when no valid span context exists",
			openTelemetryEnabled: true,
			detailedRecording:    true,
			setupContext: func(ctx context.Context) context.Context {
				return ctx
			},
			expectedTraceID: "",
			expectHeader:    false,
			description:     "Header should not be added when no valid span context exists",
		},
		{
			name:                 "should not add X-Tyk-Trace-Id header when span context is invalid",
			openTelemetryEnabled: true,
			detailedRecording:    true,
			setupContext: func(ctx context.Context) context.Context {
				spanCtx := trace.SpanContext{}
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "",
			expectHeader:    false,
		},
		{
			name:                 "should not add X-Tyk-Trace-Id header when detailed recording is disabled",
			openTelemetryEnabled: true,
			detailedRecording:    false,
			setupContext: func(ctx context.Context) context.Context {
				traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
				spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
				spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
				})
				return trace.ContextWithSpanContext(ctx, spanCtx)
			},
			expectedTraceID: "",
			expectHeader:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			globalConf := ts.Gw.GetConfig()
			globalConf.OpenTelemetry.Enabled = tc.openTelemetryEnabled
			globalConf.EnableAnalytics = true

			// Create API spec
			spec := BuildAPI(func(spec *APISpec) {
				spec.Name = "test-api"
				spec.APIID = "test-api-id"
				spec.Proxy.ListenPath = "/test"
				spec.GlobalConfig.OpenTelemetry.Enabled = tc.openTelemetryEnabled
				spec.GlobalConfig.EnableAnalytics = true
				spec.DoNotTrack = false
				spec.EnableDetailedRecording = tc.detailedRecording // Use test case setting for detailed recording
			})[0]

			ts.Gw.LoadAPI(spec)

			var capturedResponse *http.Response
			ts.Gw.Analytics.mockEnabled = true
			ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {}

			req, _ := http.NewRequest("GET", "/test", nil)
			ctx := req.Context()
			if tc.setupContext != nil {
				ctx = tc.setupContext(ctx)
			}
			req = req.WithContext(ctx)

			mockResponse := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       http.NoBody,
			}

			successHandler := &SuccessHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
					Gw:   ts.Gw,
				},
			}

			successHandler.RecordHit(req, analytics.Latency{Total: 100}, 200, mockResponse, false)
			capturedResponse = mockResponse

			if tc.expectHeader {
				headerValue := capturedResponse.Header.Get("X-Tyk-Trace-Id")
				assert.NotEmpty(t, headerValue, "X-Tyk-Trace-Id header should be present")
				assert.Equal(t, tc.expectedTraceID, headerValue, tc.description)
			} else {
				headerValue := capturedResponse.Header.Get("X-Tyk-Trace-Id")
				assert.Empty(t, headerValue, "X-Tyk-Trace-Id header should not be present")
			}

			assert.Equal(t, 200, capturedResponse.StatusCode, "Response code should be preserved")
		})
	}
}
