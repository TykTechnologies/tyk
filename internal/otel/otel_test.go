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

		givenConfig  Config
		givenVersion string
		givenId      string
		setupFn      func() (string, func())
		expectedType string
	}{
		{
			testName: "opentelemetry disabled",
			givenConfig: Config{
				Enabled: false,
			},
			expectedType: tyktrace.NOOP_PROVIDER,
		},
		{
			testName: "opentelemetry enabled, exporter set to http",
			givenConfig: Config{
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
			givenConfig: Config{
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
			givenConfig: Config{
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

			provider := InitOpenTelemetry(ctx, logrus.New(), &tc.givenConfig, tc.givenId, tc.givenVersion)
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

func TestGatewaySpanAttributes(t *testing.T) {
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
			attrs := GatewaySpanAttributes(tt.gwID, tt.isHybrid, tt.groupID, tt.isSegmented, tt.segmentTags)
			assert.Equal(t, tt.expectedAttr, attrs)
		})
	}
}

func TestContextWithSpan(t *testing.T) {
	provider := InitOpenTelemetry(context.Background(), logger.GetLogger(), &Config{
		Enabled:  true,
		Endpoint: "invalid",
	}, "test", "test")

	ctx := context.Background()
	_, span := provider.Tracer().Start(context.Background(), "test operation")

	newContext := ContextWithSpan(ctx, span)

	if got := SpanFromContext(newContext); got != span {
		t.Errorf("got wrong span")
	}
}
