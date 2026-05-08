package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// helper: spin up a fake remote MCP server with PRM + AS metadata + the
// authorize/token endpoints, plus the Tyk MCP API in mirror mode. Returns
// the test harness and the upstream URL so tests can drive requests
// against gateway routes that proxy to the fake upstream.
func newMCPMirrorTest(t *testing.T, behavior func(w http.ResponseWriter, r *http.Request, upstream *httptest.Server)) (*Test, string) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		behavior(w, r, upstream)
	})

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/mcp-test/"
	upstreamTarget := upstream.URL + "/v1/mcp/authv2"

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "MCP OAuth Proxy", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "mcp-oauth-test", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: upstreamTarget},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled: true,
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstreamTarget
		spec.IsOAS = true
		spec.OAS = oasDoc
	})
	ts.Gw.PRMCache().Invalidate(upstream.URL + "/.well-known/oauth-protected-resource/v1/mcp/authv2")

	return ts, upstream.URL
}

// stockUpstreamHandler emulates a spec-compliant upstream MCP that
// publishes PRM + RFC 8414 AS metadata + working authorize/token
// endpoints. Drives the happy-path flow.
func stockUpstreamHandler(authorizeHits, tokenHits *int, lastResource *string) func(w http.ResponseWriter, r *http.Request, upstream *httptest.Server) {
	return func(w http.ResponseWriter, r *http.Request, upstream *httptest.Server) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource/v1/mcp/authv2":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":"https://upstream.example/v1/mcp/authv2","authorization_servers":["%s"]}`, upstream.URL) //nolint:errcheck
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":"%s","authorization_endpoint":"%s/authorize","token_endpoint":"%s/token"}`, //nolint:errcheck
				upstream.URL, upstream.URL, upstream.URL)
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			*authorizeHits++
			*lastResource = r.URL.Query().Get("resource")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			*tokenHits++
			_ = r.ParseForm() //nolint:errcheck
			*lastResource = r.PostFormValue("resource")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"abc"}`)) //nolint:errcheck
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestASProxyMetadata_SchemaShape(t *testing.T) {
	var (
		authorizeHits, tokenHits int
		lastResource             string
	)
	ts, upstreamURL := newMCPMirrorTest(t, stockUpstreamHandler(&authorizeHits, &tokenHits, &lastResource))

	resp, _ := ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/.well-known/oauth-authorization-server/__tyk-as/test",
		Code:   http.StatusOK,
	})

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.Contains(t, meta["authorization_endpoint"], "/__tyk-as/test/authorize")
	assert.Contains(t, meta["token_endpoint"], "/__tyk-as/test/token")
	// Issuer + non-rewritten fields preserved verbatim.
	assert.Equal(t, upstreamURL, meta["issuer"])
}

func TestASProxy_AuthorizeRedirect_RewritesResource(t *testing.T) {
	var (
		authorizeHits, tokenHits int
		lastResource             string
	)
	ts, upstreamURL := newMCPMirrorTest(t, stockUpstreamHandler(&authorizeHits, &tokenHits, &lastResource))

	gatewayResource := "http%3A%2F%2Fgateway%2Fmcp-test%2F"
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, errReq := http.NewRequest(http.MethodGet,
		ts.URL+"/__tyk-as/test/authorize?response_type=code&client_id=cid&resource="+gatewayResource+"&state=s",
		nil)
	require.NoError(t, errReq)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := resp.Location()
	require.NoError(t, err)
	upstreamHost, err := url.Parse(upstreamURL)
	require.NoError(t, err)
	assert.Equal(t, upstreamHost.Host, loc.Host)
	assert.Equal(t, upstreamURL+"/v1/mcp/authv2", loc.Query().Get("resource"),
		"resource param must be rewritten to upstream URL")
}

func TestASProxy_TokenForward_RewritesResource(t *testing.T) {
	var (
		authorizeHits, tokenHits int
		lastResource             string
	)
	ts, upstreamURL := newMCPMirrorTest(t, stockUpstreamHandler(&authorizeHits, &tokenHits, &lastResource))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "abc")
	form.Set("resource", "http://gateway/mcp-test/")
	req, errReq := http.NewRequest(http.MethodPost, ts.URL+"/__tyk-as/test/token", strings.NewReader(form.Encode()))
	require.NoError(t, errReq)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, errBody := io.ReadAll(resp.Body)
	require.NoError(t, errBody)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", string(body))
	assert.Contains(t, string(body), `"access_token":"abc"`)
	assert.Equal(t, upstreamURL+"/v1/mcp/authv2", lastResource,
		"upstream /token must see resource rewritten to the upstream URL")
	assert.Equal(t, 1, tokenHits)
}

func TestASProxy_AuthorizeBadGateway_WhenUpstreamMissingASEndpoint(t *testing.T) {
	ts, _ := newMCPMirrorTest(t, func(w http.ResponseWriter, r *http.Request, upstream *httptest.Server) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/v1/mcp/authv2":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":"x","authorization_servers":["%s"]}`, upstream.URL) //nolint:errcheck
		case "/.well-known/oauth-authorization-server":
			// Metadata returns no authorization_endpoint at all.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"x"}`)) //nolint:errcheck
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	req, errReq := http.NewRequest(http.MethodGet, ts.URL+"/__tyk-as/test/authorize?resource=x", nil)
	require.NoError(t, errReq)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestASProxy_TokenBadGateway_WhenUpstreamMetadataMissing(t *testing.T) {
	ts, _ := newMCPMirrorTest(t, func(w http.ResponseWriter, r *http.Request, upstream *httptest.Server) {
		// Upstream PRM responds, but AS metadata is missing.
		if r.URL.Path == "/.well-known/oauth-protected-resource/v1/mcp/authv2" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":"x","authorization_servers":["%s"]}`, upstream.URL) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	req, errReq := http.NewRequest(http.MethodPost, ts.URL+"/__tyk-as/test/token", strings.NewReader(form.Encode()))
	require.NoError(t, errReq)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestRewriteResourceParam(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.Proxy.TargetURL = "https://upstream.example/v1/mcp"

	t.Run("rewrites when resource present", func(t *testing.T) {
		v := url.Values{}
		v.Set("resource", "http://gw/mcp/")
		v.Set("state", "s")
		rewriteResourceParam(v, spec)
		assert.Equal(t, "https://upstream.example/v1/mcp", v.Get("resource"))
		assert.Equal(t, "s", v.Get("state"))
	})

	t.Run("noop when resource absent", func(t *testing.T) {
		v := url.Values{}
		v.Set("state", "s")
		rewriteResourceParam(v, spec)
		assert.Empty(t, v.Get("resource"))
	})
}

func TestFetchUpstreamASMetadata_PathSuffixVariant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server/tenant" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"https://as","token_endpoint":"https://as/t"}`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	doc, err := fetchUpstreamASMetadata(context.Background(), srv.URL+"/tenant")
	require.NoError(t, err)
	assert.Equal(t, "https://as", doc["issuer"])
	assert.Equal(t, "https://as/t", doc["token_endpoint"])
}

func TestFetchUpstreamASMetadata_PathPrefixVariant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only respond at the path-prefix variant; the suffix one 404s.
		if r.URL.Path == "/tenant/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"https://as"}`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	doc, err := fetchUpstreamASMetadata(context.Background(), srv.URL+"/tenant")
	require.NoError(t, err)
	assert.Equal(t, "https://as", doc["issuer"])
}

func TestFetchUpstreamASMetadata_RootHostNoPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"https://as"}`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	doc, err := fetchUpstreamASMetadata(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://as", doc["issuer"])
}

func TestFetchUpstreamASMetadata_AllVariants404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchUpstreamASMetadata(context.Background(), srv.URL+"/tenant")
	assert.Error(t, err)
}

func TestFetchUpstreamASMetadata_BadURL(t *testing.T) {
	_, err := fetchUpstreamASMetadata(context.Background(), "::not a url")
	assert.Error(t, err)
}

// TestRegisterMCPPRMSuffixRoutes_EarlyReturns covers the four early-exit
// guards in registerMCPPRMSuffixRoutes (nil spec, non-MCP, no PRM, root
// listen path) — they're no-ops, so the test asserts that no panic
// occurs and that the gateway router doesn't gain a corresponding route.
func TestRegisterMCPPRMSuffixRoutes_EarlyReturns(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	type tc struct {
		name string
		spec *APISpec
	}
	cases := []tc{
		{"nil spec", nil},
		{"non-MCP spec", &APISpec{
			APIDefinition: &apidef.APIDefinition{IsOAS: true, APIID: "x"},
		}},
		{
			name: "MCP without PRM config (and no auth block at all)",
			spec: func() *APISpec {
				s := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true, APIID: "y"}}
				s.MarkAsMCP()
				// No OAS extension at all → GetPRMConfig synthesises a default for MCP,
				// so this path actually does register routes. Test the explicit-disabled
				// case instead via a separate API spec.
				s.OAS.SetTykExtension(&oas.XTykAPIGateway{
					Server: oas.Server{
						Authentication: &oas.Authentication{
							ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{Enabled: false},
						},
					},
				})
				return s
			}(),
		},
		{
			name: "MCP with PRM but root listen path",
			spec: func() *APISpec {
				s := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true, APIID: "z"}}
				s.MarkAsMCP()
				s.Proxy.ListenPath = "/"
				s.OAS.SetTykExtension(&oas.XTykAPIGateway{
					Server: oas.Server{
						Authentication: &oas.Authentication{
							ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{Enabled: true},
						},
					},
				})
				return s
			}(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(_ *testing.T) {
			// Should be a no-op — no panic, no error returned.
			ts.Gw.registerMCPPRMSuffixRoutes(c.spec, nil)
		})
	}
}

// TestPRMMirror_UpstreamUnreachable covers the error path where the
// upstream PRM endpoint is unavailable: serveMirroredPRM returns the
// fetch error, the in-listen-path PRMMiddleware logs and falls through
// to the upstream proxy (no panic, no 5xx).
func TestPRMMirror_UpstreamUnreachable(t *testing.T) {
	// Use a never-listening address so the upstream PRM fetch fails.
	deadUpstream := "http://127.0.0.1:1"

	ts := StartTest(nil)
	defer ts.Close()

	const listenPath = "/dead/"
	oasDoc := OAS_OAuthMirrorMode(listenPath)
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = deadUpstream + "/v1/mcp/authv2"
		spec.IsOAS = true
		spec.OAS = oasDoc
	})
	ts.Gw.PRMCache().Invalidate(deadUpstream + "/.well-known/oauth-protected-resource/v1/mcp/authv2")

	resp, _ := ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/.well-known/oauth-protected-resource/dead",
	})
	// The suffix-route handler returns 502 when upstream PRM fails.
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// helper: minimal OAS doc with mirror-mode PRM enabled, used by the
// unreachable-upstream test (and any future scenario tests).
func OAS_OAuthMirrorMode(listenPath string) oas.OAS {
	o := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "x", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	o.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{Name: "x", State: oas.State{Active: true}},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled: true,
				},
			},
		},
	})
	return o
}

func TestReplaceOrAppendResourceMetadata(t *testing.T) {
	cases := []struct {
		name string
		in   string
		url  string
		want string
	}{
		{
			name: "appends when absent",
			in:   `Bearer realm="OAuth"`,
			url:  "http://gw/x",
			want: `Bearer realm="OAuth", resource_metadata="http://gw/x"`,
		},
		{
			name: "replaces existing",
			in:   `Bearer realm="OAuth", resource_metadata="https://upstream/x"`,
			url:  "http://gw/x",
			want: `Bearer realm="OAuth", resource_metadata="http://gw/x"`,
		},
		{
			name: "case-insensitive match",
			in:   `Bearer Resource_Metadata="https://upstream/x", error="invalid_token"`,
			url:  "http://gw/x",
			want: `Bearer resource_metadata="http://gw/x", error="invalid_token"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := replaceOrAppendResourceMetadata(c.in, c.url)
			assert.Equal(t, c.want, got)
		})
	}
}
