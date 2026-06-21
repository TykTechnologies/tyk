package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
