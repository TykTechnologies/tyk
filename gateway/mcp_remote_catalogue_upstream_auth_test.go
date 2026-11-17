//go:build ee || dev

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// The catalogue check uses the same upstream authentication middleware as the
// proxy, which is an Enterprise Edition feature.

func TestRemoteMCPCatalogue_UpstreamAuth(t *testing.T) {
	t.Run("upstream basic auth is sent to the catalogue check", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		var gotAuth string
		var mu sync.Mutex
		fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotAuth = r.Header.Get("Authorization")
			mu.Unlock()
			fake.ServeHTTP(w, r)
		}))
		t.Cleanup(upstream.Close)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-basic-auth", upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		}, func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled:   true,
				BasicAuth: apidef.UpstreamBasicAuth{Enabled: true, Username: "catalogue", Password: "check"},
			}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "Basic Y2F0YWxvZ3VlOmNoZWNr", gotAuth)
	})

	t.Run("a redirecting upstream is not followed and the credential stays put", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-redirect"
		logs := recordRemoteMCPLogs(t, apiID)

		var redirectedHits int
		var mu sync.Mutex
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			mu.Lock()
			redirectedHits++
			mu.Unlock()
		}))
		t.Cleanup(target.Close)
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/mcp", http.StatusFound)
		}))
		t.Cleanup(origin.Close)

		spec := loadRemoteMCPProxy(t, ts, apiID, origin.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		}, func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled: true, Username: "catalogue", Password: "check",
					Header: apidef.AuthSource{Enabled: true, Name: "X-Upstream-Auth"},
				},
			}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		mu.Lock()
		assert.Zero(t, redirectedHits, "the redirect target must never be contacted")
		mu.Unlock()
		assert.NotNil(t, spec.MCPToolView(), "a redirect is handled like an unreachable upstream")
		assert.NotNil(t, logs.find(logrus.WarnLevel, "302"))
	})

	t.Run("upstream OAuth client credentials token is sent to the catalogue check", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		tokens := newFakeOAuthTokenServer(t, "client_credentials", "cc-token")
		upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-oauth-cc", upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{Enabled: true, OAuth: apidef.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{"clientCredentials"},
				ClientCredentials: apidef.ClientCredentials{
					ClientAuthData: apidef.ClientAuthData{ClientID: "catalogue-client", ClientSecret: "catalogue-secret"},
					TokenURL:       tokens.URL,
					Scopes:         []string{"tools"},
				},
			}}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.Equal(t, "Bearer cc-token", seen.get("Authorization"))
	})

	t.Run("upstream OAuth client credentials token honours the custom header", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		tokens := newFakeOAuthTokenServer(t, "client_credentials", "cc-header-token")
		upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-oauth-cc-header", upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{Enabled: true, OAuth: apidef.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{"clientCredentials"},
				ClientCredentials: apidef.ClientCredentials{
					ClientAuthData: apidef.ClientAuthData{ClientID: "catalogue-client", ClientSecret: "catalogue-secret"},
					TokenURL:       tokens.URL,
					Header:         apidef.AuthSource{Enabled: true, Name: "X-Upstream-Token"},
				},
			}}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.Equal(t, "Bearer cc-header-token", seen.get("X-Upstream-Token"))
		assert.Empty(t, seen.get("Authorization"))
	})

	t.Run("upstream OAuth password token is sent to the catalogue check", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		tokens := newFakeOAuthTokenServer(t, "password", "pw-token")
		upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-oauth-password", upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{Enabled: true, OAuth: apidef.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{"password"},
				PasswordAuthentication: apidef.PasswordAuthentication{
					ClientAuthData: apidef.ClientAuthData{ClientID: "catalogue-client", ClientSecret: "catalogue-secret"},
					Username:       "catalogue-user",
					Password:       "catalogue-password",
					TokenURL:       tokens.URL,
				},
			}}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.Equal(t, "Bearer pw-token", seen.get("Authorization"))
	})

	t.Run("a failing token endpoint is reported like an unreachable upstream", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-oauth-failure"
		logs := recordRemoteMCPLogs(t, apiID)
		tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		}))
		t.Cleanup(tokens.Close)
		upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{Enabled: true, OAuth: apidef.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{"clientCredentials"},
				ClientCredentials: apidef.ClientCredentials{
					ClientAuthData: apidef.ClientAuthData{ClientID: "catalogue-client", ClientSecret: "wrong"},
					TokenURL:       tokens.URL,
				},
			}}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.NotNil(t, spec.MCPToolView())
		assert.NotNil(t, logs.find(logrus.WarnLevel, "applying them unchecked"))
		assert.Zero(t, seen.count(), "the upstream is not called without its credential")
	})
}

// newFakeOAuthTokenServer issues token for grantType and rejects anything else.
func newFakeOAuthTokenServer(t *testing.T, grantType, token string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != grantType {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		if grantType == "password" && (r.PostForm.Get("username") != "catalogue-user" || r.PostForm.Get("password") != "catalogue-password") {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 3600})
	}))
	t.Cleanup(server.Close)
	return server
}
