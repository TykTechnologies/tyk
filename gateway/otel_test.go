package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	"github.com/TykTechnologies/tyk/config"
)

func Test_InitOTel(t *testing.T) {
	tcs := []struct {
		testName string

		givenConfig config.Config
		setupFn     func() (string, func())
	}{
		{
			testName: "opentelemetry disabled",
			givenConfig: config.Config{
				OpenTelemetry: otelconfig.OpenTelemetry{
					Enabled: false,
				},
			},
		},
		{
			testName: "opentelemetry enabled, exporter set to http",
			givenConfig: config.Config{
				OpenTelemetry: otelconfig.OpenTelemetry{
					Enabled:  true,
					Exporter: "http",
					Endpoint: "http://localhost:4317",
				},
			},
			setupFn: func() (string, func()) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Here you can check the request and return a response
					w.WriteHeader(http.StatusOK)
				}))

				return server.URL, server.Close
			},
		},
		{
			testName: "opentelemetry enabled, exporter set to grpc",
			givenConfig: config.Config{
				OpenTelemetry: otelconfig.OpenTelemetry{
					Enabled:  true,
					Exporter: "grpc",
					Endpoint: "localhost:4317",
				},
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
		},
		{
			testName: "opentelemetry enabled, exporter set to invalid - noop provider should be used",
			givenConfig: config.Config{
				OpenTelemetry: otelconfig.OpenTelemetry{
					Enabled:  true,
					Exporter: "invalid",
					Endpoint: "localhost:4317",
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			gw := &Gateway{}
			gw.ctx = context.Background()

			if tc.setupFn != nil {
				endpoint, teardown := tc.setupFn()
				defer teardown()

				tc.givenConfig.OpenTelemetry.Endpoint = endpoint
			}

			gw.SetConfig(tc.givenConfig)
			gw.afterConfSetup()

			gw.InitOpenTelemetry()
			assert.NotNil(t, gw.TraceProvider)
		})
	}
}
