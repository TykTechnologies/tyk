package gateway

import (
	"bytes"
	"context"
	htmltemplate "html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	texttemplate "text/template"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-074, SYS-REQ-162, SW-REQ-149
// STK-REQ-074:STK-REQ-074-AC-01:acceptance
// SW-REQ-149:nominal:nominal
// SW-REQ-149:boundary:nominal
// SW-REQ-149:boundary:boundary
// SW-REQ-149:determinism:nominal
// SYS-REQ-162:determinism:nominal
func TestGatewayAPILoaderLocalHelpers(t *testing.T) {
	t.Run("domain path key", func(t *testing.T) {
		tests := []struct {
			name       string
			host       string
			listenPath string
			want       string
		}{
			{name: "host and slash path", host: "api.example.com", listenPath: "/v1/", want: "api.example.com/v1/"},
			{name: "empty host", listenPath: "/public/", want: "/public/"},
			{name: "empty listen path", host: "api.example.com", want: "api.example.com"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, generateDomainPath(tt.host, tt.listenPath))
			})
		}
	})

	t.Run("count APIs by listen hash", func(t *testing.T) {
		specs := []*APISpec{
			apiLoaderHelperSpec("first", "api.example.com", false, "/v1/"),
			apiLoaderHelperSpec("second", "api.example.com", false, "/v1/"),
			apiLoaderHelperSpec("third", "api.example.com", false, "/v2/"),
			apiLoaderHelperSpec("domain disabled", "ignored.example.com", true, "/v1/"),
			apiLoaderHelperSpec("no host", "", false, "/v1/"),
		}

		assert.Equal(t, map[string]int{
			"api.example.com/v1/": 2,
			"api.example.com/v2/": 1,
			"/v1/":                2,
		}, countApisByListenHash(specs))
	})

	t.Run("prefix middleware function paths", func(t *testing.T) {
		functions := []apidef.MiddlewareDefinition{
			{Name: "pre", Path: "middleware/pre.js"},
			{Name: "post", Path: "middleware/post.js"},
			{Name: "empty"},
		}

		fixFuncPath("/opt/tyk", functions)

		assert.Equal(t, []apidef.MiddlewareDefinition{
			{Name: "pre", Path: "/opt/tyk/middleware/pre.js"},
			{Name: "post", Path: "/opt/tyk/middleware/post.js"},
			{Name: "empty", Path: "/opt/tyk"},
		}, functions)
	})
}

func apiLoaderHelperSpec(name, domain string, domainDisabled bool, listenPath string) *APISpec {
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Name:           name,
			Domain:         domain,
			DomainDisabled: domainDisabled,
			Proxy: apidef.ProxyConfig{
				ListenPath: listenPath,
			},
		},
	}
}

// Verifies: STK-REQ-076, SYS-REQ-164, SW-REQ-151
// STK-REQ-076:STK-REQ-076-AC-01:acceptance
// SW-REQ-151:nominal:nominal
// SW-REQ-151:boundary:nominal
// SW-REQ-151:boundary:boundary
// SW-REQ-151:determinism:nominal
// SYS-REQ-164:determinism:nominal
func TestGatewayAPILoaderSkipInvalidSpecs(t *testing.T) {
	tests := []struct {
		name          string
		protocol      string
		listenPath    string
		targetURL     string
		secrets       map[string]string
		wantSkip      bool
		wantTargetURL string
	}{
		{
			name:       "HTTP API with empty listen path is skipped",
			listenPath: "",
			targetURL:  "http://upstream.example.com",
			wantSkip:   true,
		},
		{
			name:       "HTTP API with spaces in listen path is skipped",
			listenPath: "/bad path/",
			targetURL:  "http://upstream.example.com",
			wantSkip:   true,
		},
		{
			name:       "HTTP API with valid listen path and target is accepted",
			listenPath: "/valid/",
			targetURL:  "http://upstream.example.com",
		},
		{
			name:      "non-HTTP API bypasses listen path validation",
			protocol:  "tcp",
			targetURL: "tcp://upstream.example.com:9000",
			wantSkip:  false,
		},
		{
			name:       "malformed target URL is skipped",
			listenPath: "/valid/",
			targetURL:  "://bad-url",
			wantSkip:   true,
		},
		{
			name:          "secret target URL is resolved before parsing",
			listenPath:    "/valid/",
			targetURL:     "secrets://upstream",
			secrets:       map[string]string{"upstream": "http://secret-upstream.example.com"},
			wantTargetURL: "http://secret-upstream.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{Secrets: tt.secrets}, context.Background())
			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Protocol: tt.protocol,
					Proxy: apidef.ProxyConfig{
						ListenPath: tt.listenPath,
						TargetURL:  tt.targetURL,
					},
				},
			}

			gotSkip := gw.skipSpecBecauseInvalid(spec, logrus.NewEntry(logrus.New()))

			assert.Equal(t, tt.wantSkip, gotSkip)
			if tt.wantTargetURL != "" {
				assert.Equal(t, tt.wantTargetURL, spec.Proxy.TargetURL)
			}
		})
	}
}

// Verifies: STK-REQ-077, SYS-REQ-165, SW-REQ-152
// STK-REQ-077:STK-REQ-077-AC-01:acceptance
// SW-REQ-152:nominal:nominal
// SW-REQ-152:boundary:nominal
// SW-REQ-152:boundary:boundary
// SW-REQ-152:determinism:nominal
// SYS-REQ-165:determinism:nominal
func TestGatewayAPILoaderLoopDetection(t *testing.T) {
	tests := []struct {
		name       string
		targetURL  string
		loopLevel  int
		loopLimit  int
		wantFound  bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:      "HTTP request is not a loop",
			targetURL: "http://upstream.example.com/resource",
		},
		{
			name:      "tyk request with default limit is a loop",
			targetURL: "tyk://internal/resource",
			wantFound: true,
		},
		{
			name:      "tyk request at default limit is allowed",
			targetURL: "tyk://internal/resource",
			loopLevel: defaultLoopLevelLimit,
			wantFound: true,
		},
		{
			name:       "tyk request above default limit errors",
			targetURL:  "tyk://internal/resource",
			loopLevel:  defaultLoopLevelLimit + 1,
			wantFound:  true,
			wantErr:    true,
			wantErrMsg: "Loop level too deep. Found more than 5 loops in single request",
		},
		{
			name:      "tyk request at custom limit is allowed",
			targetURL: "tyk://internal/resource",
			loopLevel: 2,
			loopLimit: 2,
			wantFound: true,
		},
		{
			name:       "tyk request above custom limit errors",
			targetURL:  "tyk://internal/resource",
			loopLevel:  3,
			loopLimit:  2,
			wantFound:  true,
			wantErr:    true,
			wantErrMsg: "Loop level too deep. Found more than 2 loops in single request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.targetURL, nil)
			ctxSetLoopLevel(req, tt.loopLevel)
			if tt.loopLimit > 0 {
				ctxSetLoopLimit(req, tt.loopLimit)
			}

			gotFound, err := isLoop(req)

			assert.Equal(t, tt.wantFound, gotFound)
			if tt.wantErr {
				assert.EqualError(t, err, tt.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Verifies: STK-REQ-078, SYS-REQ-166, SW-REQ-153
// STK-REQ-078:STK-REQ-078-AC-01:acceptance
// SW-REQ-153:nominal:nominal
// SW-REQ-153:boundary:nominal
// SW-REQ-153:boundary:boundary
// SW-REQ-153:determinism:nominal
// SYS-REQ-166:determinism:nominal
func TestGatewayAPILoaderFindInternalHTTPHandler(t *testing.T) {
	apiByID := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "api-by-id",
			Name:  "API By ID",
		},
	}
	apiByName := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "api-by-name",
			Name:  "Internal API #category",
		},
	}
	handlerByID := http.NewServeMux()
	handlerByName := http.NewServeMux()

	tests := []struct {
		name        string
		search      string
		withAPIs    []*APISpec
		withHandles map[string]http.Handler
		wantAPI     *APISpec
		wantHandler http.Handler
		wantOK      bool
	}{
		{
			name:   "missing API returns not found",
			search: "missing",
		},
		{
			name:     "matched API without handler returns not found",
			search:   apiByID.APIID,
			withAPIs: []*APISpec{apiByID},
			wantOK:   false,
		},
		{
			name:     "APIID match returns registered handler",
			search:   apiByID.APIID,
			withAPIs: []*APISpec{apiByID},
			withHandles: map[string]http.Handler{
				apiByID.APIID: handlerByID,
			},
			wantAPI:     apiByID,
			wantHandler: handlerByID,
			wantOK:      true,
		},
		{
			name:     "looping name match returns registered handler",
			search:   APILoopingName(apiByName.Name),
			withAPIs: []*APISpec{apiByName},
			withHandles: map[string]http.Handler{
				apiByName.APIID: handlerByName,
			},
			wantAPI:     apiByName,
			wantHandler: handlerByName,
			wantOK:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &Gateway{
				apisByID:        make(map[string]*APISpec),
				apisHandlesByID: new(sync.Map),
			}
			for _, spec := range tt.withAPIs {
				gw.apisByID[spec.APIID] = spec
			}
			for apiID, handler := range tt.withHandles {
				gw.apisHandlesByID.Store(apiID, &ChainObject{ThisHandler: handler})
			}

			gotHandler, gotAPI, gotOK := gw.findInternalHttpHandlerByNameOrID(tt.search)

			assert.Equal(t, tt.wantOK, gotOK)
			if tt.wantAPI == nil {
				assert.Nil(t, gotAPI)
			} else {
				assert.Same(t, tt.wantAPI, gotAPI)
			}
			if tt.wantHandler == nil {
				assert.Nil(t, gotHandler)
			} else {
				assert.Same(t, tt.wantHandler, gotHandler)
			}
		})
	}
}

// Verifies: STK-REQ-101, SYS-REQ-189, SW-REQ-176
// STK-REQ-101:STK-REQ-101-AC-01:acceptance
// STK-REQ-101:error_handling:negative
// SW-REQ-176:nominal:nominal
// SW-REQ-176:boundary:nominal
// SW-REQ-176:error_handling:nominal
// SW-REQ-176:error_handling:negative
// SW-REQ-176:determinism:nominal
// SYS-REQ-189:determinism:nominal
// SYS-REQ-189:error_handling:nominal
// SYS-REQ-189:error_handling:negative
func TestGatewayAPILoaderDummyProxyLoopDispatch(t *testing.T) {
	tests := []struct {
		name            string
		rewriteTarget   string
		sourceHandler   bool
		targetAPI       *APISpec
		targetHandler   bool
		wantStatus      int
		wantBody        string
		wantHandledBy   string
		wantMethod      string
		wantPath        string
		wantRawQuery    string
		wantLoopLevel   int
		wantLoopLimit   int
		wantCheckLimits bool
	}{
		{
			name:            "self loop dispatch applies control params and strips them",
			rewriteTarget:   "tyk://self/target?method=POST&loop_limit=3&check_limits=true&foo=bar",
			sourceHandler:   true,
			wantStatus:      http.StatusAccepted,
			wantHandledBy:   "source",
			wantMethod:      http.MethodPost,
			wantPath:        "/target",
			wantRawQuery:    "foo=bar",
			wantLoopLevel:   1,
			wantLoopLimit:   3,
			wantCheckLimits: true,
		},
		{
			name:          "named API loop dispatch selects matching loaded handler",
			rewriteTarget: "tyk://target-api/resource?foo=bar",
			targetAPI: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID: "target-api",
					Name:  "Target API",
				},
			},
			targetHandler: true,
			wantStatus:    http.StatusAccepted,
			wantHandledBy: "target",
			wantMethod:    http.MethodGet,
			wantPath:      "/resource",
			wantRawQuery:  "foo=bar",
			wantLoopLevel: 1,
		},
		{
			name:          "missing named API loop target returns local error",
			rewriteTarget: "tyk://missing-api/resource",
			wantStatus:    http.StatusInternalServerError,
			wantBody:      "detect loop target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID: "source-api",
					Name:  "Source API",
				},
			}
			metricInstruments, _ := testMetricInstruments(t, nil)
			gw := &Gateway{
				MetricInstruments: metricInstruments,
				apisByID:          make(map[string]*APISpec),
				apisHandlesByID:   new(sync.Map),
				templates:         htmltemplate.Must(htmltemplate.New("error.json").Parse(`{"error":"{{.Message}}"}`)),
			}
			gw.apisByID[sourceSpec.APIID] = sourceSpec
			if tt.targetAPI != nil {
				gw.apisByID[tt.targetAPI.APIID] = tt.targetAPI
			}

			handledBy := ""
			captureHandler := func(name string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handledBy = name
					assert.Equal(t, tt.wantMethod, r.Method)
					assert.Equal(t, tt.wantPath, r.URL.Path)
					assert.Equal(t, tt.wantRawQuery, r.URL.RawQuery)
					assert.Equal(t, tt.wantLoopLevel, ctxLoopLevel(r))
					assert.Equal(t, tt.wantLoopLimit, ctxLoopLevelLimit(r))
					assert.Equal(t, tt.wantCheckLimits, ctxCheckLimits(r))
					w.WriteHeader(http.StatusAccepted)
				})
			}
			if tt.sourceHandler {
				gw.apisHandlesByID.Store(sourceSpec.APIID, &ChainObject{ThisHandler: captureHandler("source")})
			}
			if tt.targetHandler {
				gw.apisHandlesByID.Store(tt.targetAPI.APIID, &ChainObject{ThisHandler: captureHandler("target")})
			}

			rewriteTarget, err := url.Parse(tt.rewriteTarget)
			assert.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, "http://gateway.local/entry?a=b", nil)
			ctxSetURLRewriteTarget(req, rewriteTarget)
			recorder := httptest.NewRecorder()
			handler := &DummyProxyHandler{
				SH: SuccessHandler{BaseMiddleware: &BaseMiddleware{
					Spec:   sourceSpec,
					Gw:     gw,
					logger: logrus.NewEntry(logrus.New()),
				}},
				Gw: gw,
			}

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, tt.wantStatus, recorder.Code)
			assert.Equal(t, tt.wantHandledBy, handledBy)
			assert.Nil(t, ctxGetURLRewriteTarget(req))
			if tt.wantBody != "" {
				assert.Contains(t, recorder.Body.String(), tt.wantBody)
			}
		})
	}
}

// Verifies: STK-REQ-102, SYS-REQ-190, SW-REQ-177
// STK-REQ-102:STK-REQ-102-AC-01:acceptance
// STK-REQ-102:error_handling:negative
// SW-REQ-177:nominal:nominal
// SW-REQ-177:boundary:nominal
// SW-REQ-177:error_handling:nominal
// SW-REQ-177:error_handling:negative
// SW-REQ-177:determinism:nominal
// SYS-REQ-190:determinism:nominal
// SYS-REQ-190:error_handling:nominal
// SYS-REQ-190:error_handling:negative
func TestGatewayAPILoaderReadGraphQLPlaygroundTemplate(t *testing.T) {
	previousTemplate := playgroundTemplate
	t.Cleanup(func() {
		playgroundTemplate = previousTemplate
	})

	tests := []struct {
		name          string
		setup         func(t *testing.T, root string)
		wantTemplate  bool
		wantIndexBody string
	}{
		{
			name: "valid playground templates are cached",
			setup: func(t *testing.T, root string) {
				t.Helper()
				playgroundDir := filepath.Join(root, "playground")
				assert.NoError(t, os.MkdirAll(playgroundDir, 0755))
				assert.NoError(t, os.WriteFile(filepath.Join(playgroundDir, playgroundHTMLTemplateName), []byte(`endpoint={{.Endpoint}}`), 0644))
				assert.NoError(t, os.WriteFile(filepath.Join(playgroundDir, playgroundJSTemplateName), []byte(`console.log("playground")`), 0644))
			},
			wantTemplate:  true,
			wantIndexBody: "endpoint=/graphql/",
		},
		{
			name: "missing playground directory clears cache",
			setup: func(t *testing.T, root string) {
				t.Helper()
			},
		},
		{
			name: "invalid playground template clears cache",
			setup: func(t *testing.T, root string) {
				t.Helper()
				playgroundDir := filepath.Join(root, "playground")
				assert.NoError(t, os.MkdirAll(playgroundDir, 0755))
				assert.NoError(t, os.WriteFile(filepath.Join(playgroundDir, playgroundHTMLTemplateName), []byte(`{{`), 0644))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setup(t, root)
			playgroundTemplate = texttemplate.Must(texttemplate.New("sentinel").Parse("stale"))
			gw := &Gateway{}
			gw.SetConfig(config.Config{TemplatePath: root})

			gw.readGraphqlPlaygroundTemplate()

			if !tt.wantTemplate {
				assert.Nil(t, playgroundTemplate)
				return
			}

			if assert.NotNil(t, playgroundTemplate) {
				assert.NotNil(t, playgroundTemplate.Lookup(playgroundHTMLTemplateName))
				assert.NotNil(t, playgroundTemplate.Lookup(playgroundJSTemplateName))

				var rendered bytes.Buffer
				err := playgroundTemplate.ExecuteTemplate(&rendered, playgroundHTMLTemplateName, struct {
					Endpoint string
				}{Endpoint: "/graphql/"})
				assert.NoError(t, err)
				assert.Equal(t, tt.wantIndexBody, rendered.String())
			}
		})
	}
}

// Verifies: STK-REQ-079, SYS-REQ-167, SW-REQ-154
// STK-REQ-079:STK-REQ-079-AC-01:acceptance
// SW-REQ-154:nominal:nominal
// SW-REQ-154:boundary:nominal
// SW-REQ-154:boundary:boundary
// SW-REQ-154:determinism:nominal
// SYS-REQ-167:determinism:nominal
func TestGatewayAPILoaderExplicitRouteSubpaths(t *testing.T) {
	original := http.NewServeMux()
	original.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Handled", "true")
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name     string
		prefix   string
		enabled  bool
		wantSame bool
	}{
		{name: "disabled preserves original handler", prefix: "/api", enabled: false, wantSame: true},
		{name: "trailing slash prefix preserves original handler", prefix: "/api/", enabled: true, wantSame: true},
		{name: "route parameter prefix preserves original handler", prefix: "/api/{id}", enabled: true, wantSame: true},
		{name: "simple prefix wraps handler", prefix: "/api", enabled: true, wantSame: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := explicitRouteSubpaths(tt.prefix, original, tt.enabled)
			if tt.wantSame {
				assert.Same(t, original, got)
				return
			}

			wrapped, ok := got.(*explicitRouteHandler)
			assert.True(t, ok)
			assert.Equal(t, tt.prefix, wrapped.prefix)
			assert.Same(t, original, wrapped.handler)
		})
	}

	wrapped := explicitRouteSubpaths("/api", original, true)
	requests := []struct {
		name        string
		path        string
		wantStatus  int
		wantHandled bool
	}{
		{name: "exact prefix delegates", path: "/api", wantStatus: http.StatusNoContent, wantHandled: true},
		{name: "nested subpath delegates", path: "/api/users", wantStatus: http.StatusNoContent, wantHandled: true},
		{name: "sibling path returns not found", path: "/apiary", wantStatus: http.StatusNotFound},
		{name: "outside path returns not found", path: "/other", wantStatus: http.StatusNotFound},
	}

	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			wrapped.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))

			assert.Equal(t, tt.wantStatus, recorder.Code)
			if tt.wantHandled {
				assert.Equal(t, "true", recorder.Header().Get("X-Handled"))
			} else {
				assert.Empty(t, recorder.Header().Get("X-Handled"))
				assert.Equal(t, http.StatusText(http.StatusNotFound), recorder.Body.String())
			}
		})
	}
}
