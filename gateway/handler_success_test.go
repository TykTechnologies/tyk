package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/test"
	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	ctxpkg "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/otel"
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
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			req := testRequestWithContext(tc.binding)
			got := recordDetail(req, tc.spec)
			assert.Equal(t, tc.expect, got)
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

func TestAddTraceID(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		hasTraceID bool
		wantHeader bool
	}{
		{
			name:       "otel enabled with trace id",
			enabled:    true,
			hasTraceID: true,
			wantHeader: true,
		},
		{
			name:       "otel enabled without trace id",
			enabled:    true,
			hasTraceID: false,
			wantHeader: false,
		},
		{
			name:       "otel disabled",
			enabled:    false,
			hasTraceID: false,
			wantHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			otelConfig := otel.Config{
				Enabled:  tt.enabled,
				Exporter: "http",
				Endpoint: "http://localhost:4317",
			}

			gwConfig := config.Config{
				OpenTelemetry: otelConfig,
			}

			if tt.hasTraceID {
				ot := otel.InitOpenTelemetry(context.Background(), logrus.New(), &otelConfig, "test", "test", false, "test", false, []string{})
				ctx, _ := ot.Tracer().Start(context.Background(), "testing")
				req = req.WithContext(ctx)
			}

			addTraceID(w, req, gwConfig)

			if tt.wantHeader && w.Header().Get("X-Tyk-Trace-Id") == "" {
				t.Errorf("expected header to be set, but it wasn't")
			} else if !tt.wantHeader && w.Header().Get("X-Tyk-Trace-Id") != "" {
				t.Errorf("expected header not to be set, but it was")
			}
		})
	}
}
