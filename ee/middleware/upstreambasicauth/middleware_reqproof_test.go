package upstreambasicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/service/core"
)

type upstreamBasicAuthTestBaseMiddleware struct{}

func (upstreamBasicAuthTestBaseMiddleware) Logger() *logrus.Entry {
	return logrus.NewEntry(logrus.New())
}

type upstreamBasicAuthTestGateway struct{}

func (upstreamBasicAuthTestGateway) GetConfig() config.Config {
	return config.Config{}
}

func (upstreamBasicAuthTestGateway) ReplaceTykVariables(_ *http.Request, in string, _ bool) string {
	return in
}

func upstreamBasicAuthSpec(auth apidef.UpstreamAuth) *APISpec {
	return NewAPISpec("api-id", "upstream-basic", true, oas.OAS{}, auth)
}

// Verifies: STK-REQ-040, SYS-REQ-128, SW-REQ-115
// STK-REQ-040:STK-REQ-040-AC-01:acceptance
// STK-REQ-040:STK-REQ-040-AC-02:acceptance
// SYS-REQ-128:nominal:nominal
// MCDC SYS-REQ-128: upstream_basic_auth_operation_terminal=T => TRUE
// SW-REQ-115:nominal:nominal
// SW-REQ-115:boundary:nominal
// SW-REQ-115:error_handling:nominal
// SW-REQ-115:determinism:nominal
//
//mcdc:ignore SYS-REQ-128: upstream_basic_auth_operation_terminal=F => FALSE -- the onboarded upstream basic auth operations are synchronous local helpers that either return an enablement decision, install a provider in request context, or update a request header before returning; a non-terminal result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestUpstreamBasicAuthMiddlewarePreservesLocalBehavior(t *testing.T) {
	t.Run("enabled for spec requires global upstream auth and basic auth enablement", func(t *testing.T) {
		tests := []struct {
			name string
			auth apidef.UpstreamAuth
			want bool
		}{
			{
				name: "upstream auth disabled",
				auth: apidef.UpstreamAuth{
					Enabled:   false,
					BasicAuth: apidef.UpstreamBasicAuth{Enabled: true},
				},
				want: false,
			},
			{
				name: "upstream auth enabled but basic auth disabled",
				auth: apidef.UpstreamAuth{
					Enabled: true,
					OAuth:   apidef.UpstreamOAuth{Enabled: true},
				},
				want: false,
			},
			{
				name: "upstream basic auth enabled",
				auth: apidef.UpstreamAuth{
					Enabled:   true,
					BasicAuth: apidef.UpstreamBasicAuth{Enabled: true},
				},
				want: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				middleware := NewMiddleware(upstreamBasicAuthTestGateway{}, upstreamBasicAuthTestBaseMiddleware{}, upstreamBasicAuthSpec(tt.auth))
				assert.Equal(t, tt.want, middleware.EnabledForSpec())
			})
		}
	})

	t.Run("process request installs provider with default or custom header", func(t *testing.T) {
		tests := []struct {
			name       string
			authSource apidef.AuthSource
			wantHeader string
		}{
			{
				name:       "disabled auth source uses authorization header",
				authSource: apidef.AuthSource{Enabled: false, Name: "X-Upstream-Authorization"},
				wantHeader: header.Authorization,
			},
			{
				name:       "enabled auth source uses configured header",
				authSource: apidef.AuthSource{Enabled: true, Name: "X-Upstream-Authorization"},
				wantHeader: "X-Upstream-Authorization",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				middleware := NewMiddleware(
					upstreamBasicAuthTestGateway{},
					upstreamBasicAuthTestBaseMiddleware{},
					upstreamBasicAuthSpec(apidef.UpstreamAuth{
						Enabled: true,
						BasicAuth: apidef.UpstreamBasicAuth{
							Enabled:  true,
							Username: "user",
							Password: "pass",
							Header:   tt.authSource,
						},
					}),
				)

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				err, status := middleware.ProcessRequest(httptest.NewRecorder(), req, nil)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)

				provider, ok := core.GetUpstreamAuth(req).(Provider)
				require.True(t, ok)
				assert.Equal(t, tt.wantHeader, provider.HeaderName)
				assert.Equal(t, "Basic dXNlcjpwYXNz", provider.AuthValue)
			})
		}
	})

	t.Run("constructor preserves API spec fields", func(t *testing.T) {
		auth := apidef.UpstreamAuth{Enabled: true, BasicAuth: apidef.UpstreamBasicAuth{Enabled: true}}
		spec := upstreamBasicAuthSpec(auth)

		assert.Equal(t, "api-id", spec.APIID)
		assert.Equal(t, "upstream-basic", spec.Name)
		assert.True(t, spec.IsOAS)
		assert.Equal(t, auth, spec.UpstreamAuth)
	})
}

// Verifies: STK-REQ-040, SYS-REQ-128, SW-REQ-115
// STK-REQ-040:STK-REQ-040-AC-03:acceptance
// STK-REQ-040:error_handling:negative
// SW-REQ-115:error_handling:negative
func TestUpstreamBasicAuthProviderOverwritesExistingHeader(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		want     string
	}{
		{name: "empty header is filled", existing: "", want: "Basic dXNlcjpwYXNz"},
		{name: "existing header is overwritten", existing: "Bearer caller-token", want: "Basic dXNlcjpwYXNz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.existing != "" {
				req.Header.Set(header.Authorization, tt.existing)
			}

			provider := Provider{
				Logger:     logrus.NewEntry(logrus.New()),
				HeaderName: header.Authorization,
				AuthValue:  tt.want,
			}
			provider.Fill(req)

			assert.Equal(t, tt.want, req.Header.Get(header.Authorization))
		})
	}
}
