package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func Test_InitOTel(t *testing.T) {
	tcs := []struct {
		testName string

		givenConfig config.Config
		setupFn     func() (string, func())
		expectedErr error
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
			expectedErr: nil,
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

			actualErr := gw.initOtel()
			assert.Equal(t, tc.expectedErr, actualErr)

			if tc.expectedErr == nil {
				assert.NotNil(t, gw.TraceProvider)
			}

		})
	}
}
