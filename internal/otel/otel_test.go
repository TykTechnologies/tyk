package otel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk-pump/logger"

	"github.com/sirupsen/logrus"

	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func Test_InitOpenTelemetry(t *testing.T) {
	tcs := []struct {
		testName string

		givenConfig  OpenTelemetry
		givenVersion string
		givenId      string
		setupFn      func() (string, func())
		expectedType string
	}{
		{
			testName: "opentelemetry disabled",
			givenConfig: OpenTelemetry{
				Enabled: false,
			},
			expectedType: tyktrace.NOOP_PROVIDER,
		},
		{
			testName: "opentelemetry enabled, exporter set to http",
			givenConfig: OpenTelemetry{
				Enabled:  true,
				Exporter: "http",
				Endpoint: "http://localhost:4317",
			},
			setupFn: func() (string, func()) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Here you can check the request and return a response
					w.WriteHeader(http.StatusOK)
				}))

				return server.URL, server.Close
			},
			expectedType: tyktrace.OTEL_PROVIDER,
		},
		{
			testName: "opentelemetry enabled, exporter set to grpc",
			givenConfig: OpenTelemetry{
				Enabled:  true,
				Exporter: "grpc",
				Endpoint: "localhost:4317",
			},
			setupFn: func() (string, func()) {
				lis, err := net.Listen("tcp", "localhost:0")
				if err != nil {
					t.Fatalf("failed to listen: %v", err)
				}

				// Create a gRPC server and serve on the listener
				s := grpc.NewServer()
				go func() {
					if err := s.Serve(lis); err != nil {
						t.Logf("failed to serve: %v", err)
					}
				}()

				return lis.Addr().String(), s.Stop
			},
			expectedType: tyktrace.OTEL_PROVIDER,
		},
		{
			testName: "opentelemetry enabled, exporter set to invalid - noop provider should be used",
			givenConfig: OpenTelemetry{
				Enabled:  true,
				Exporter: "invalid",
				Endpoint: "localhost:4317",
			},
			expectedType: tyktrace.NOOP_PROVIDER,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			ctx := context.Background()

			if tc.setupFn != nil {
				endpoint, teardown := tc.setupFn()
				defer teardown()

				tc.givenConfig.Endpoint = endpoint
			}

			provider := InitOpenTelemetry(ctx, logrus.New(), &tc.givenConfig, tc.givenId, tc.givenVersion, false, "", false, []string{})
			assert.NotNil(t, provider)

			assert.Equal(t, tc.expectedType, provider.Type())
		})
	}
}

func Test_ApidefSpanAttributes(t *testing.T) {
	tcs := []struct {
		name               string
		givenApidef        *apidef.APIDefinition
		expectedAttributes []SpanAttribute
	}{
		{
			name: "Apidef without tags",
			givenApidef: &apidef.APIDefinition{
				APIID: "id",
				OrgID: "org1",
				Name:  "testapi",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/test",
				},
				TagsDisabled: true,
			},
			expectedAttributes: []SpanAttribute{
				tyktrace.NewAttribute(string(semconv.TykAPIIDKey), "id"),
				tyktrace.NewAttribute(string(semconv.TykAPIOrgIDKey), "org1"),
				tyktrace.NewAttribute(string(semconv.TykAPINameKey), "testapi"),
				tyktrace.NewAttribute(string(semconv.TykAPIListenPathKey), "/test"),
			},
		},
		{
			name: "Apidef with tags",
			givenApidef: &apidef.APIDefinition{
				APIID: "id",
				OrgID: "org1",
				Name:  "testapi",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/test",
				},
				TagsDisabled: false,
				Tags:         []string{"tag1", "tag2"},
				TagHeaders:   []string{"tag3"},
			},
			expectedAttributes: []SpanAttribute{
				tyktrace.NewAttribute(string(semconv.TykAPIIDKey), "id"),
				tyktrace.NewAttribute(string(semconv.TykAPIOrgIDKey), "org1"),
				tyktrace.NewAttribute(string(semconv.TykAPINameKey), "testapi"),
				tyktrace.NewAttribute(string(semconv.TykAPIListenPathKey), "/test"),
				tyktrace.NewAttribute(string(semconv.TykAPITagsKey), []string{"tag1", "tag2", "tag3"}),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual := ApidefSpanAttributes(tc.givenApidef)

			assert.ElementsMatch(t, actual, tc.expectedAttributes)
		})
	}
}

func Test_APIVersionAttribute(t *testing.T) {
	tcs := []struct {
		name                   string
		givenVersion           string
		exepectedSpanAttribute SpanAttribute
	}{
		{
			name:                   "empty version",
			givenVersion:           "",
			exepectedSpanAttribute: tyktrace.NewAttribute(string(semconv.TykAPIVersionKey), NON_VERSIONED),
		},
		{
			name:                   "with version",
			givenVersion:           "test",
			exepectedSpanAttribute: tyktrace.NewAttribute(string(semconv.TykAPIVersionKey), "test"),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual := APIVersionAttribute(tc.givenVersion)
			assert.Equal(t, tc.exepectedSpanAttribute, actual)
		})
	}
}

func TestGatewayResourceAttributes(t *testing.T) {
	tests := []struct {
		name         string
		gwID         string
		isHybrid     bool
		groupID      string
		isSegmented  bool
		segmentTags  []string
		expectedAttr []SpanAttribute
	}{
		{
			name:        "Non-hybrid, non-segmented gateway",
			gwID:        "gw1",
			isHybrid:    false,
			groupID:     "",
			isSegmented: false,
			segmentTags: nil,
			expectedAttr: []SpanAttribute{
				tyktrace.NewAttribute(string(semconv.TykGWIDKey), "gw1"),
				tyktrace.NewAttribute(string(semconv.TykGWDataplaneKey), false),
			},
		},
		{
			name:        "Hybrid, non-segmented gateway",
			gwID:        "gw2",
			isHybrid:    true,
			groupID:     "group1",
			isSegmented: false,
			segmentTags: nil,
			expectedAttr: []SpanAttribute{
				tyktrace.NewAttribute(string(semconv.TykGWIDKey), "gw2"),
				tyktrace.NewAttribute(string(semconv.TykGWDataplaneKey), true),
				tyktrace.NewAttribute(string(semconv.TykDataplaneGWGroupIDKey), "group1"),
			},
		},
		{
			name:        "Hybrid, segmented gateway",
			gwID:        "gw3",
			isHybrid:    true,
			groupID:     "group2",
			isSegmented: true,
			segmentTags: []string{"tag1", "tag2"},
			expectedAttr: []SpanAttribute{
				tyktrace.NewAttribute(string(semconv.TykGWIDKey), "gw3"),
				tyktrace.NewAttribute(string(semconv.TykGWDataplaneKey), true),
				tyktrace.NewAttribute(string(semconv.TykDataplaneGWGroupIDKey), "group2"),
				tyktrace.NewAttribute(string(semconv.TykGWSegmentTagsKey), []string{"tag1", "tag2"}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := GatewayResourceAttributes(tt.gwID, tt.isHybrid, tt.groupID, tt.isSegmented, tt.segmentTags)
			assert.Equal(t, tt.expectedAttr, attrs)
		})
	}
}

func TestContextWithSpan(t *testing.T) {
	provider := InitOpenTelemetry(context.Background(), logger.GetLogger(), &OpenTelemetry{
		Enabled:  true,
		Endpoint: "invalid",
	}, "test", "test", false, "", false, []string{})

	ctx := context.Background()
	_, span := provider.Tracer().Start(context.Background(), "test operation")

	newContext := ContextWithSpan(ctx, span)

	if got := SpanFromContext(newContext); got != span {
		t.Errorf("got wrong span")
	}
}

func makeHTTPCollector(t *testing.T) (endpoint string, cleanup func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return srv.URL, srv.Close
}

func makeProviderHTTP(t *testing.T) tyktrace.Provider {
	t.Helper()
	endpoint, cleanup := makeHTTPCollector(t)
	t.Cleanup(cleanup)

	cfg := &OpenTelemetry{
		Enabled:  true,
		Exporter: "http",
		Endpoint: endpoint,
	}

	provider := InitOpenTelemetry(context.Background(), logrus.New(), cfg,
		"gw-id-1", "v1.2.3", false, "", false, nil)

	assert.NotNil(t, provider)
	assert.Equal(t, tyktrace.OTEL_PROVIDER, provider.Type())

	return provider
}

func TestExtractTraceID(t *testing.T) {
	t.Run("returns empty when no span in context", func(t *testing.T) {
		got := ExtractTraceID(context.Background())
		assert.Equal(t, "", got)
	})

	t.Run("returns non-empty trace id when span is present", func(t *testing.T) {
		provider := makeProviderHTTP(t)

		ctx := context.Background()
		_, span := provider.Tracer().Start(ctx, "extract-traceid-test")
		defer span.End()

		ctx = ContextWithSpan(ctx, span)

		got := ExtractTraceID(ctx)
		assert.NotEmpty(t, got, "expected non-empty trace id")
		assert.Equal(t, span.SpanContext().TraceID().String(), got)
	})
}

func TestAddTraceID(t *testing.T) {
	t.Run("does not set header when no span", func(t *testing.T) {
		rr := httptest.NewRecorder()

		AddTraceID(context.Background(), rr)

		assert.Empty(t, rr.Header().Get(TykTraceIDHeader))
	})

	t.Run("sets header when span has trace id", func(t *testing.T) {
		provider := makeProviderHTTP(t)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		ctx := req.Context()

		_, span := provider.Tracer().Start(ctx, "add-traceid-test")
		defer span.End()

		ctx = ContextWithSpan(ctx, span)

		rr := httptest.NewRecorder()
		AddTraceID(ctx, rr)

		h := rr.Header().Get(TykTraceIDHeader)
		assert.NotEmpty(t, h, "expected X-Tyk-Trace-Id header to be set")
		assert.Equal(t, span.SpanContext().TraceID().String(), h)
	})
}

// TestExtractTraceID_WithRequest verifies ExtractTraceID correctly extracts
// trace IDs from request contexts in various scenarios.
func TestExtractTraceID_WithRequest(t *testing.T) {

	tests := []struct {
		name          string
		setupContext  func(provider tyktrace.Provider) (context.Context, tyktrace.Span)
		expectTraceID bool
	}{
		{
			name: "empty context - no trace ID",
			setupContext: func(_ tyktrace.Provider) (context.Context, tyktrace.Span) {
				return context.Background(), nil
			},
			expectTraceID: false,
		},
		{
			name: "valid span context - trace ID present",
			setupContext: func(provider tyktrace.Provider) (context.Context, tyktrace.Span) {
				ctx := context.Background()
				_, span := provider.Tracer().Start(ctx, "access-log-test")
				ctx = ContextWithSpan(ctx, span)
				return ctx, span
			},
			expectTraceID: true,
		},
	}

	provider := makeProviderHTTP(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, span := tc.setupContext(provider)
			if span != nil {
				defer span.End()
			}

			// Test ExtractTraceID directly with request context
			req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			req = req.WithContext(ctx)

			traceID := ExtractTraceID(req.Context())
			hasTraceID := traceID != ""
			assert.Equal(t, tc.expectTraceID, hasTraceID)

			if tc.expectTraceID && span != nil {
				assert.Equal(t, span.SpanContext().TraceID().String(), traceID)
			}
		})
	}
}
