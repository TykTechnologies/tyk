package streams

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

type streamTestBaseMiddleware struct{}

func (streamTestBaseMiddleware) Logger() *logrus.Entry {
	return testLogger()
}

type streamTestGateway struct {
	cfg          config.Config
	replacements map[string]string
}

func (g *streamTestGateway) GetConfig() config.Config {
	return g.cfg
}

func (g *streamTestGateway) ReplaceTykVariables(_ *http.Request, in string, _ bool) string {
	for oldValue, newValue := range g.replacements {
		in = strings.ReplaceAll(in, oldValue, newValue)
	}
	return in
}

type streamTestAnalyticsFactory struct{}

func (streamTestAnalyticsFactory) CreateRecorder(_ *http.Request) StreamAnalyticsRecorder {
	return &NoopStreamAnalyticsRecorder{}
}

func (streamTestAnalyticsFactory) CreateResponseWriter(w http.ResponseWriter, _ *http.Request, _ string, _ StreamAnalyticsRecorder) http.ResponseWriter {
	return w
}

// Verifies: STK-REQ-039, SYS-REQ-127, SW-REQ-114
// SYS-REQ-127:nominal:nominal
// MCDC SYS-REQ-127: enterprise_stream_operation_terminal=T => TRUE
// SW-REQ-114:nominal:nominal
// SW-REQ-114:boundary:nominal
// SW-REQ-114:error_handling:nominal
// SW-REQ-114:determinism:nominal
//
//mcdc:ignore SYS-REQ-127: enterprise_stream_operation_terminal=F => FALSE -- the onboarded stream middleware operations are synchronous local helpers that either return a value, return an explicit error, or update deterministic in-memory state before returning; a non-terminal result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestEnterpriseStreamsLocalHelpersPreserveBehavior(t *testing.T) {
	t.Run("HTTP path extraction covers defaults brokers and deduplication", func(t *testing.T) {
		tests := []struct {
			name   string
			config map[string]interface{}
			want   []string
		}{
			{
				name: "direct HTTP server paths use defaults when absent",
				config: map[string]interface{}{
					"input": map[string]interface{}{
						"http_server": map[string]interface{}{},
					},
				},
				want: []string{"/post", "/post/ws", "/get/stream"},
			},
			{
				name: "direct input and output paths are deduplicated",
				config: map[string]interface{}{
					"input": map[string]interface{}{
						"http_server": map[string]interface{}{
							"path":        "/post",
							"ws_path":     "/subscribe",
							"stream_path": "/events",
						},
					},
					"output": map[string]interface{}{
						"http_server": map[string]interface{}{
							"path":        "/post",
							"ws_path":     "/subscribe-two",
							"stream_path": "/events",
						},
					},
				},
				want: []string{"/post", "/subscribe", "/subscribe-two", "/events"},
			},
			{
				name: "broker inputs and outputs expose nested HTTP server paths",
				config: map[string]interface{}{
					"input": map[string]interface{}{
						"broker": map[string]interface{}{
							"inputs": []interface{}{
								map[string]interface{}{
									"http_server": map[string]interface{}{
										"path":        "/broker-in",
										"ws_path":     "/broker-ws",
										"stream_path": "/broker-stream",
									},
								},
							},
							"outputs": []interface{}{
								map[string]interface{}{
									"http_server": map[string]interface{}{
										"path": "/broker-out",
									},
								},
							},
						},
					},
				},
				want: []string{"/broker-in", "/broker-ws", "/broker-stream", "/broker-out", "/post/ws", "/get/stream"},
			},
			{
				name:   "non HTTP components return no paths",
				config: map[string]interface{}{"input": map[string]interface{}{"generate": map[string]interface{}{}}},
				want:   nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.ElementsMatch(t, tt.want, GetHTTPPaths(tt.config))
			})
		}
	})

	t.Run("manager path matching normalizes leading slashes", func(t *testing.T) {
		manager := &Manager{listenPaths: []string{"/events", "plain"}}
		tests := []struct {
			name string
			path string
			want bool
		}{
			{name: "absolute path matches configured absolute path", path: "/events", want: true},
			{name: "relative path matches configured absolute path", path: "events", want: true},
			{name: "absolute path matches configured relative path", path: "/plain", want: true},
			{name: "unknown path is rejected", path: "/missing", want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, manager.hasPath(tt.path))
			})
		}
	})

	t.Run("stream config extraction replaces request scoped variables", func(t *testing.T) {
		oasDoc := oas.OAS{}
		oasDoc.SetTykStreamingExtension(&oas.XTykStreaming{
			Streams: map[string]interface{}{
				"orders": map[string]interface{}{
					"input": map[string]interface{}{
						"http_server": map[string]interface{}{
							"path": "${stream_path}",
						},
					},
				},
			},
		})

		mw := NewMiddleware(
			&streamTestGateway{replacements: map[string]string{"${stream_path}": "/tenant/orders"}},
			streamTestBaseMiddleware{},
			NewAPISpec("api-id", "orders", true, oasDoc, func(path string) string { return path }),
			nil,
		)

		streamsConfig := mw.getStreamsConfig(httptest.NewRequest(http.MethodGet, "/tenant/orders", nil))
		require.Contains(t, streamsConfig.Streams, "orders")

		streamConfig, ok := streamsConfig.Streams["orders"].(map[string]interface{})
		require.True(t, ok)
		input, ok := streamConfig["input"].(map[string]interface{})
		require.True(t, ok)
		httpServer, ok := input["http_server"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "/tenant/orders", httpServer["path"])
	})

	t.Run("non OAS specs expose empty stream configuration", func(t *testing.T) {
		mw := NewMiddleware(
			&streamTestGateway{},
			streamTestBaseMiddleware{},
			NewAPISpec("classic-api", "classic", false, oas.OAS{}, func(path string) string { return path }),
			nil,
		)
		assert.Empty(t, mw.getStreamsConfig(nil).Streams)
	})

	t.Run("analytics factory fallback preserves no-op behavior", func(t *testing.T) {
		tests := []struct {
			name    string
			factory StreamAnalyticsFactory
			want    any
		}{
			{name: "nil factory falls back to no-op", factory: nil, want: &NoopStreamAnalyticsFactory{}},
			{name: "custom factory is preserved", factory: streamTestAnalyticsFactory{}, want: streamTestAnalyticsFactory{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				manager := &Manager{}
				manager.SetAnalyticsFactory(tt.factory)
				assert.IsType(t, tt.want, manager.analyticsFactory)
			})
		}
	})

	t.Run("missing streaming route returns not found before handler dispatch", func(t *testing.T) {
		mw := NewMiddleware(
			&streamTestGateway{},
			streamTestBaseMiddleware{},
			NewAPISpec("api-id", "orders", true, oas.OAS{}, func(path string) string { return path }),
			nil,
		)
		mw.defaultManager = &Manager{
			muxer:       mux.NewRouter(),
			listenPaths: []string{"/events"},
		}

		err, status := mw.ProcessRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/missing", nil), nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "not found", err.Error())
	})

	t.Run("matched default route returns OK without per request handler dispatch", func(t *testing.T) {
		mw := NewMiddleware(
			&streamTestGateway{},
			streamTestBaseMiddleware{},
			NewAPISpec("api-id", "orders", true, oas.OAS{}, func(path string) string { return path }),
			nil,
		)
		mw.defaultManager = &Manager{
			muxer:       mux.NewRouter(),
			listenPaths: []string{"/events"},
		}

		err, status := mw.ProcessRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil), nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
}

// Verifies: SYS-REQ-127, SW-REQ-114
// SW-REQ-114:nominal:nominal
func TestEnterpriseStreamsAnalyticsNoopRecorderPreservesBehavior(t *testing.T) {
	recorder := (&NoopStreamAnalyticsFactory{}).CreateRecorder(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NotNil(t, recorder)

	recorder.PrepareRecord(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, recorder.RecordHit(http.StatusAccepted, analytics.Latency{}))

	response := httptest.NewRecorder()
	wrapped := (&NoopStreamAnalyticsFactory{}).CreateResponseWriter(response, httptest.NewRequest(http.MethodGet, "/", nil), "stream", recorder)
	assert.Same(t, response, wrapped)
}
