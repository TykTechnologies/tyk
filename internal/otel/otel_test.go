package otel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	tyktrace "github.com/TykTechnologies/opentelemetry/trace"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func Test_InitOpenTelemetry(t *testing.T) {
	tcs := []struct {
		testName string

		givenConfig  Config
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

			provider := InitOpenTelemetry(ctx, logrus.New(), &tc.givenConfig)
			assert.NotNil(t, provider)

			assert.Equal(t, tc.expectedType, provider.Type())
		})
	}
}
