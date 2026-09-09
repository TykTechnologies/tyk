package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	otel "github.com/TykTechnologies/tyk/internal/otel"
	tykregexp "github.com/TykTechnologies/tyk/regexp"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestTrackEndpointMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     *APISpec
		expected bool
	}{
		{
			name: "disabled when DoNotTrack is true",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					DoNotTrack: true,
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
				},
			},
			expected: false,
		},
		{
			name: "disabled when neither analytics nor metrics enabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{},
				GlobalConfig:  config.Config{},
			},
			expected: false,
		},
		{
			name: "disabled when analytics enabled but no track endpoints configured",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
				},
			},
			expected: false,
		},
		{
			name: "enabled when analytics enabled and TrackEndpoints configured",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
				},
			},
			expected: true,
		},
		{
			name: "enabled when analytics enabled and DoNotTrackEndpoints configured",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									DoNotTrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/untracked", Method: "POST"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
				},
			},
			expected: true,
		},
		{
			name: "enabled when only metrics enabled and TrackEndpoints configured",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: false,
					OpenTelemetry: otel.OpenTelemetry{
						Metrics: otel.MetricsConfig{
							BaseMetricsConfig: otel.BaseMetricsConfig{
								Enabled: boolPtr(true),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "disabled when metrics Enabled is nil",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: false,
					OpenTelemetry: otel.OpenTelemetry{
						Metrics: otel.MetricsConfig{
							BaseMetricsConfig: otel.BaseMetricsConfig{
								Enabled: nil,
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "disabled when metrics Enabled is false",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"Default": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: false,
					OpenTelemetry: otel.OpenTelemetry{
						Metrics: otel.MetricsConfig{
							BaseMetricsConfig: otel.BaseMetricsConfig{
								Enabled: boolPtr(false),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "enabled when both analytics and metrics enabled with track endpoints",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"v1": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
					OpenTelemetry: otel.OpenTelemetry{
						Metrics: otel.MetricsConfig{
							BaseMetricsConfig: otel.BaseMetricsConfig{
								Enabled: boolPtr(true),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "enabled when track endpoints in any version",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"v1": {},
							"v2": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									TrackEndpoints: []apidef.TrackEndpointMeta{
										{Path: "/tracked", Method: "GET"},
									},
								},
							},
						},
					},
				},
				GlobalConfig: config.Config{
					EnableAnalytics: true,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &TrackEndpointMiddleware{
				BaseMiddleware: &BaseMiddleware{Spec: tt.spec},
			}
			assert.Equal(t, tt.expected, mw.EnabledForSpec())
		})
	}
}

func TestTrackEndpointMiddleware_ProcessRequest(t *testing.T) {
	type expectedCtx struct {
		trackedPath string
		doNotTrack  bool
	}

	tests := []struct {
		name        string
		givenAPI    *APISpec
		method      string
		path        string
		expectedCtx expectedCtx
	}{
		{
			name: "sets tracked path when request matches tracked endpoint",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/tracked"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/tracked",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/tracked",
			expectedCtx: expectedCtx{
				trackedPath: "/tracked",
				doNotTrack:  false,
			},
		},
		{
			name: "sets do-not-track when request matches do-not-track endpoint",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/health"),
							Status: RequestNotTracked,
							DoNotTrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/health",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/health",
			expectedCtx: expectedCtx{
				trackedPath: "",
				doNotTrack:  true,
			},
		},
		{
			name: "no context set when request does not match any endpoint",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/tracked"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/tracked",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/other",
			expectedCtx: expectedCtx{
				trackedPath: "",
				doNotTrack:  false,
			},
		},
		{
			name: "no match when method differs",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/tracked"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/tracked",
								Method: "POST",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/tracked",
			expectedCtx: expectedCtx{
				trackedPath: "",
				doNotTrack:  false,
			},
		},
		{
			name: "matches parameterized path like /status/{status_id}",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/status/([^/]+)"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/status/{status_id}",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/status/42",
			expectedCtx: expectedCtx{
				trackedPath: "/status/{status_id}",
				doNotTrack:  false,
			},
		},
		{
			name: "regex path does not match different segment structure",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/status/([^/]+)"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/status/{status_id}",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/status/42/details",
			expectedCtx: expectedCtx{
				trackedPath: "/status/{status_id}",
				doNotTrack:  false,
			},
		},
		{
			name: "do-not-track with wildcard path /internal/*",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/internal/.*"),
							Status: RequestNotTracked,
							DoNotTrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/internal/*",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/internal/debug/pprof",
			expectedCtx: expectedCtx{
				trackedPath: "",
				doNotTrack:  true,
			},
		},
		{
			name: "regex does not match completely different path",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/users/([^/]+)/orders"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/users/{user_id}/orders",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/products/123",
			expectedCtx: expectedCtx{
				trackedPath: "",
				doNotTrack:  false,
			},
		},
		{
			name: "matches multi-segment parameterized path /users/{id}/orders/{order_id}",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/users/([^/]+)/orders/([^/]+)"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/users/{id}/orders/{order_id}",
								Method: "POST",
							},
						},
					},
				},
			},
			method: "POST",
			path:   "/users/abc-123/orders/ord-456",
			expectedCtx: expectedCtx{
				trackedPath: "/users/{id}/orders/{order_id}",
				doNotTrack:  false,
			},
		},
		{
			name: "both tracked and do-not-track can be set simultaneously",
			givenAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						NotVersioned:   true,
						DefaultVersion: "Default",
						Versions: map[string]apidef.VersionInfo{
							"Default": {Name: "Default"},
						},
					},
					Proxy: apidef.ProxyConfig{
						ListenPath: "/",
					},
				},
				RxPaths: map[string][]URLSpec{
					"Default": {
						{
							spec:   tykregexp.MustCompile("/both"),
							Status: RequestTracked,
							TrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/both",
								Method: "GET",
							},
						},
						{
							spec:   tykregexp.MustCompile("/both"),
							Status: RequestNotTracked,
							DoNotTrackEndpoint: apidef.TrackEndpointMeta{
								Path:   "/both",
								Method: "GET",
							},
						},
					},
				},
			},
			method: "GET",
			path:   "/both",
			expectedCtx: expectedCtx{
				trackedPath: "/both",
				doNotTrack:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &TrackEndpointMiddleware{
				BaseMiddleware: &BaseMiddleware{Spec: tt.givenAPI},
			}

			r := httptest.NewRequest(tt.method, tt.path, nil)
			err, code := mw.ProcessRequest(nil, r, nil)

			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, tt.expectedCtx.trackedPath, ctxGetTrackedPath(r))
			assert.Equal(t, tt.expectedCtx.doNotTrack, ctxGetDoNotTrack(r))
		})
	}
}

func TestTrackEndpointMiddleware_Name(t *testing.T) {
	mw := &TrackEndpointMiddleware{}
	assert.Equal(t, "TrackEndpointMiddleware", mw.Name())
}
