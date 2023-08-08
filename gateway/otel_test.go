//go:build v52
// +build v52

package gateway

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/test"
)

func TestGateway_afterConfSetup(t *testing.T) {

	tests := []struct {
		name           string
		initialConfig  config.Config
		expectedConfig config.Config
	}{
		{
			name: "slave options test",
			initialConfig: config.Config{
				SlaveOptions: config.SlaveOptionsConfig{
					UseRPC: true,
				},
			},
			expectedConfig: config.Config{
				SlaveOptions: config.SlaveOptionsConfig{
					UseRPC:                   true,
					GroupID:                  "ungrouped",
					CallTimeout:              30,
					PingTimeout:              60,
					KeySpaceSyncInterval:     10,
					RPCCertCacheExpiration:   3600,
					RPCGlobalCacheExpiration: 30,
				},
				AnalyticsConfig: config.AnalyticsConfigConfig{
					PurgeInterval: 10,
				},
				HealthCheckEndpointName: "hello",
			},
		},
		{
			name: "opentelemetry options test",
			initialConfig: config.Config{
				Features: config.Features{
					OpenTelemetry: otel.Config{
						Enabled: true,
					},
				},
			},
			expectedConfig: config.Config{
				Features: config.Features{
					OpenTelemetry: otel.Config{
						Enabled:            true,
						Exporter:           "grpc",
						Endpoint:           "localhost:4317",
						ResourceName:       "tyk-gateway",
						SpanProcessorType:  "batch",
						ConnectionTimeout:  1,
						ContextPropagation: "tracecontext",
						Sampling: otel.Sampling{
							Type: "AlwaysOn",
						},
					},
				},
				AnalyticsConfig: config.AnalyticsConfigConfig{
					PurgeInterval: 10,
				},
				HealthCheckEndpointName: "hello",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(tt.initialConfig, context.Background())
			gw.afterConfSetup()

			assert.Equal(t, tt.expectedConfig, gw.GetConfig())

		})
	}
}

func TestOpenTelemetry(t *testing.T) {
	t.Run("Opentelemetry enabled - check if we are sending traces", func(t *testing.T) {
		otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
			//check the body
			body, err := io.ReadAll(r.Body)
			assert.Nil(t, err)

			assert.NotEmpty(t, body)

			// check the user agent
			agent, ok := r.Header["User-Agent"]
			assert.True(t, ok)
			assert.Len(t, agent, 1)
			assert.Contains(t, agent[0], "OTLP")

			//check if we are sending the traces to the right endpoint
			assert.Contains(t, r.URL.Path, "/v1/traces")

			// Here you can check the request and return a response
			w.WriteHeader(http.StatusOK)
		}, ":0")

		// Start the server.
		otelCollectorMock.Start()
		// Stop the server on return from the function.
		defer otelCollectorMock.Close()

		ts := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = true
			globalConf.OpenTelemetry.Exporter = "http"
			globalConf.OpenTelemetry.Endpoint = otelCollectorMock.URL
			globalConf.OpenTelemetry.SpanProcessorType = "simple"
		})
		defer ts.Close()
		detailedTracing := []bool{true, false}
		for _, detailed := range detailedTracing {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = "test"
				spec.Proxy.ListenPath = "/my-api/"
				spec.UseKeylessAccess = true
				spec.DetailedTracing = detailed
			})

			_, _ = ts.Run(t, test.TestCase{Path: "/my-api/", Code: http.StatusOK})
			assert.Equal(t, "otel", ts.Gw.TracerProvider.Type())
		}

	})

	t.Run("Opentelemetry disabled - check if we are not sending traces", func(t *testing.T) {

		otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fail()
		}, ":0")

		// Start the server.
		otelCollectorMock.Start()
		// Stop the server on return from the function.
		defer otelCollectorMock.Close()

		ts := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = false
			globalConf.OpenTelemetry.Exporter = "http"
			globalConf.OpenTelemetry.Endpoint = otelCollectorMock.URL
			globalConf.OpenTelemetry.SpanProcessorType = "simple"
		})
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "test"
			spec.Proxy.ListenPath = "/my-api/"
			spec.UseKeylessAccess = true
		})

		_, _ = ts.Run(t, test.TestCase{Path: "/my-api/", Code: http.StatusOK})
		assert.Equal(t, "noop", ts.Gw.TracerProvider.Type())
	})
}
