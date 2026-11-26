package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// hostRecorder is an upstream that counts the requests it receives and keeps
// the last Authorization header, so a test can show that a request, and the
// API's injected credentials, never reached it.
type hostRecorder struct {
	*httptest.Server
	hits int32
	auth atomic.Value
}

func newHostRecorder(t *testing.T) *hostRecorder {
	t.Helper()
	h := &hostRecorder{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&h.hits, 1)
		h.auth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hostRecorder) reset() { atomic.StoreInt32(&h.hits, 0) }

func (h *hostRecorder) assertNotReached(t *testing.T) {
	t.Helper()
	assert.Zero(t, atomic.LoadInt32(&h.hits),
		"request reached a host chosen by the API client (Authorization=%v)", h.auth.Load())
}

// upstreamPath returns the path that the default test upstream received.
func upstreamPath(t *testing.T, body []byte) string {
	t.Helper()
	var resp TestHttpResponse
	require.NoError(t, json.Unmarshal(body, &resp), "response did not come from the API's upstream: %s", body)
	u, err := url.Parse(resp.Url)
	require.NoError(t, err)
	return u.Path
}

func classicRewriteAPI(apiID, rewriteTo string, triggers ...apidef.RoutingTrigger) func(*APISpec) {
	return func(spec *APISpec) {
		spec.APIID = apiID
		spec.Name = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.Proxy.StripListenPath = true
		spec.UseKeylessAccess = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalHeaders = map[string]string{"Authorization": "Bearer UPSTREAM-SECRET"}
			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/q",
				Method:       http.MethodGet,
				MatchPattern: `^/` + apiID + `/q\?u=(.*)$`,
				RewriteTo:    rewriteTo,
				Triggers:     triggers,
			}}
		})
	}
}

func oasRewriteAPI(t *testing.T, apiID, rewriteTo string) *APISpec {
	t.Helper()

	desc := ""
	oasAPI := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
	}}
	oasAPI.Paths.Set("/q", &openapi3.PathItem{Get: &openapi3.Operation{
		OperationID: "qget",
		Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
			Value: &openapi3.Response{Description: &desc},
		})),
	}})
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: apiID, ID: apiID, State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: TestHttpAny},
		Server:   oas.Server{ListenPath: oas.ListenPath{Value: "/" + apiID + "/", Strip: true}},
		Middleware: &oas.Middleware{Operations: oas.Operations{
			"qget": &oas.Operation{URLRewrite: &oas.URLRewrite{
				Enabled:   true,
				Pattern:   `^/` + apiID + `/q\?u=(.*)$`,
				RewriteTo: rewriteTo,
			}},
		}},
	})

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	for name, v := range def.VersionData.Versions {
		v.GlobalHeaders = map[string]string{"Authorization": "Bearer UPSTREAM-SECRET"}
		def.VersionData.Versions[name] = v
	}
	return &APISpec{APIDefinition: &def, OAS: oasAPI}
}

// TestURLRewrite_RequestValueAtStartOfRewriteToIsNotLoaded covers the load-time
// check: an API whose rewrite_to starts with a value from the request is
// skipped, so it never serves traffic, while other APIs still load.
func TestURLRewrite_RequestValueAtStartOfRewriteToIsNotLoaded(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	rogue := newHostRecorder(t)

	notLoaded := func(t *testing.T, path string, headers map[string]string) {
		t.Helper()
		rogue.reset()
		_, _ = ts.Run(t, test.TestCase{Path: path, Headers: headers, Code: http.StatusNotFound})
		rogue.assertNotReached(t)
	}

	t.Run("numbered capture, classic", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("capture", "$1"))
		notLoaded(t, "/capture/q?u="+rogue.URL+"/secret", nil)
	})

	t.Run("whole match, classic", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("whole", "$0"))
		notLoaded(t, "/whole/q?u=x", nil)
	})

	t.Run("request context value, classic", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("ctxhdr", "$tyk_context.headers_X_Target"))
		notLoaded(t, "/ctxhdr/q?u=x", map[string]string{"X-Target": rogue.URL + "/ctx"})
	})

	t.Run("trigger rewrite_to, classic", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("trigger", "/safe", apidef.RoutingTrigger{
			On: apidef.Any,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{"u": {MatchPattern: "(.+)"}},
			},
			RewriteTo: "$tyk_context.trigger-0-u-0",
		}))
		notLoaded(t, "/trigger/q?u="+rogue.URL+"/secret", nil)
	})

	t.Run("numbered capture, OAS", func(t *testing.T) {
		ts.Gw.LoadAPI(oasRewriteAPI(t, "oascapture", "$1"))
		notLoaded(t, "/oascapture/q?u="+rogue.URL+"/secret", nil)
	})

	t.Run("other APIs still load", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(
			classicRewriteAPI("bad", "$1"),
			classicRewriteAPI("good", "/api/$1"),
		)
		notLoaded(t, "/bad/q?u=x", nil)
		_, _ = ts.Run(t, test.TestCase{Path: "/good/q?u=x", Code: http.StatusOK})
	})

	t.Run("disabled rule does not stop the API loading", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			classicRewriteAPI("disabled", "$1")(spec)
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.URLRewrite[0].Disabled = true
			})
		})
		_, _ = ts.Run(t, test.TestCase{Path: "/disabled/q?u=x", Code: http.StatusOK})
	})
}

// TestURLRewrite_LiteralPrefixKeepsRequestOnTarget covers the forms that keep
// loading: a literal prefix before a capture keeps the request on target_url.
func TestURLRewrite_LiteralPrefixKeepsRequestOnTarget(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	rogue := newHostRecorder(t)

	for _, rewriteTo := range []string{"/$1", "/api/$1"} {
		t.Run(rewriteTo, func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(classicRewriteAPI("prefix", rewriteTo))

			_, _ = ts.Run(t, test.TestCase{
				Path: "/prefix/q?u=segment",
				Code: http.StatusOK,
				BodyMatchFunc: func(body []byte) bool {
					assert.Contains(t, upstreamPath(t, body), "segment")
					return true
				},
			})

			rogue.reset()
			_, _ = ts.Run(t, test.TestCase{Path: "/prefix/q?u=" + rogue.URL + "/secret"})
			rogue.assertNotReached(t)
		})
	}

	t.Run("OAS", func(t *testing.T) {
		ts.Gw.LoadAPI(oasRewriteAPI(t, "oasprefix", "/$1"))
		_, _ = ts.Run(t, test.TestCase{Path: "/oasprefix/q?u=segment", Code: http.StatusOK})

		rogue.reset()
		_, _ = ts.Run(t, test.TestCase{Path: "/oasprefix/q?u=" + rogue.URL + "/secret"})
		rogue.assertNotReached(t)
	})
}

// TestURLRewrite_APIManagerValuesCanStillChooseHost covers the values that only
// the API manager sets: they can still send the request to another server.
func TestURLRewrite_APIManagerValuesCanStillChooseHost(t *testing.T) {
	other := newHostRecorder(t)

	ts := StartTest(func(conf *config.Config) {
		conf.Secrets = map[string]string{"target": other.URL}
	})
	defer ts.Close()

	t.Run("literal host", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("literal", other.URL+"/fixed"))
		other.reset()
		_, _ = ts.Run(t, test.TestCase{Path: "/literal/q?u=x", Code: http.StatusOK})
		assert.Equal(t, int32(1), atomic.LoadInt32(&other.hits))
	})

	t.Run("secret reference", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("secret", "$secret_conf.target/s"))
		other.reset()
		_, _ = ts.Run(t, test.TestCase{Path: "/secret/q?u=x", Code: http.StatusOK})
		assert.Equal(t, int32(1), atomic.LoadInt32(&other.hits))
	})

	t.Run("session metadata", func(t *testing.T) {
		spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			classicRewriteAPI("meta", "$tyk_meta.target/m")(spec)
			spec.UseKeylessAccess = false
		})[0]
		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				spec.APIID: {APIName: spec.Name, APIID: spec.APIID, Versions: []string{"v1"}},
			}
			s.OrgID = spec.OrgID
			s.MetaData = map[string]interface{}{"target": other.URL}
		})
		other.reset()
		_, _ = ts.Run(t, test.TestCase{
			Path: "/meta/q?u=x", Headers: map[string]string{"Authorization": key}, Code: http.StatusOK,
		})
		assert.Equal(t, int32(1), atomic.LoadInt32(&other.hits))
	})
}
