package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	ctxpkg "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/otel"
)

// noopMetricInstruments creates a disabled MetricInstruments suitable for unit tests.
func noopMetricInstruments(t *testing.T) *otel.MetricInstruments {
	t.Helper()
	cfg := &otel.MetricsConfig{}
	provider, err := otel.NewMetricProvider(context.Background(), logrus.New(), &cfg.BaseMetricsConfig, "test-node", "v0.0.0-test")
	if err != nil {
		t.Fatalf("creating noop metric provider: %v", err)
	}
	return otel.NewMetricInstruments(provider, logrus.New())
}

func TestBaseMiddleware_RecordMetrics(t *testing.T) {
	tests := []struct {
		name           string
		doNotTrackSpec bool
		doNotTrackCtx  bool
		response       *http.Response
		statusCode     int
		wantPanic      bool
	}{
		{
			name:       "success path with response",
			statusCode: 200,
			response: &http.Response{
				Header: http.Header{"X-Cache": []string{"HIT"}},
			},
		},
		{
			name:       "error path nil response",
			statusCode: 500,
			response:   nil,
		},
		{
			name:           "skipped when DoNotTrack on spec",
			doNotTrackSpec: true,
			statusCode:     200,
		},
		{
			name:          "skipped when DoNotTrack on context",
			doNotTrackCtx: true,
			statusCode:    200,
		},
		{
			name:           "skipped when both DoNotTrack flags set",
			doNotTrackSpec: true,
			doNotTrackCtx:  true,
			statusCode:     200,
		},
		{
			name:       "zero latency values",
			statusCode: 204,
		},
		{
			name:       "4xx status code",
			statusCode: 429,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)

			if tt.doNotTrackCtx {
				setCtxValue(r, ctxpkg.DoNotTrackThisEndpoint, true)
			}

			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID: "test-api",
					Name:  "TestAPI",
					OrgID: "test-org",
					Proxy: apidef.ProxyConfig{
						ListenPath: "/test",
					},
					DoNotTrack: tt.doNotTrackSpec,
				},
			}

			gw := &Gateway{
				MetricInstruments: noopMetricInstruments(t),
			}

			bm := &BaseMiddleware{
				Spec: spec,
				Gw:   gw,
			}

			latency := analytics.Latency{
				Total:    150,
				Upstream: 100,
				Gateway:  50,
			}

			assert.NotPanics(t, func() {
				bm.RecordMetrics(r, tt.statusCode, latency, tt.response)
			})
		})
	}
}
