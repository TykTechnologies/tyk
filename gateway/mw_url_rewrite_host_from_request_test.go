package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/test"
)

// TestURLRewrite_RequestValueCannotCompleteTheHost covers the runtime check for
// rewrite_to values that load: a request value after a literal or API manager
// host must not change the scheme, user info, host or port.
func TestURLRewrite_RequestValueCannotCompleteTheHost(t *testing.T) {
	rogue := newHostRecorder(t)
	upstream := newHostRecorder(t)
	rogueHostPort := strings.TrimPrefix(rogue.URL, "http://")
	roguePort := rogueHostPort[strings.LastIndex(rogueHostPort, ":"):]

	ts := StartTest(func(conf *config.Config) {
		conf.Secrets = map[string]string{"upstream": upstream.URL}
	})
	defer ts.Close()

	blocked := func(t *testing.T, path string) {
		t.Helper()
		rogue.reset()
		upstream.reset()

		_, _ = ts.Run(t, test.TestCase{Path: path, Code: http.StatusBadRequest})
		rogue.assertNotReached(t)
		assert.Zero(t, atomic.LoadInt32(&upstream.hits), "nothing should be sent upstream")
	}

	t.Run("user info trick after a literal host", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("userinfo", upstream.URL+"$1"))
		blocked(t, "/userinfo/q?u=@"+rogueHostPort+"/secret")
	})

	t.Run("user info trick after a secret reference", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("secretinfo", "$secret_conf.upstream$1"))
		blocked(t, "/secretinfo/q?u=@"+rogueHostPort+"/secret")
	})

	t.Run("port from the request", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("port", "http://127.0.0.1$1"))
		blocked(t, "/port/q?u="+roguePort+"/secret")
	})

	t.Run("trigger rewrite_to", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("trigger", "/safe", apidef.RoutingTrigger{
			On: apidef.Any,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{"u": {MatchPattern: ".+"}},
			},
			RewriteTo: upstream.URL + "$1",
		}))
		blocked(t, "/trigger/q?u=@"+rogueHostPort+"/secret")
	})

	t.Run("OAS", func(t *testing.T) {
		ts.Gw.LoadAPI(oasRewriteAPI(t, "oasinfo", upstream.URL+"$1"))
		blocked(t, "/oasinfo/q?u=@"+rogueHostPort+"/secret")
	})

	t.Run("path after a literal host is still allowed", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("hostpath", upstream.URL+"$1"))
		upstream.reset()

		_, _ = ts.Run(t, test.TestCase{Path: "/hostpath/q?u=/ok", Code: http.StatusOK})
		assert.Equal(t, int32(1), atomic.LoadInt32(&upstream.hits))
	})

	t.Run("path after a secret reference is still allowed", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(classicRewriteAPI("secretpath", "$secret_conf.upstream$1"))
		upstream.reset()

		_, _ = ts.Run(t, test.TestCase{Path: "/secretpath/q?u=/ok", Code: http.StatusOK})
		assert.Equal(t, int32(1), atomic.LoadInt32(&upstream.hits))
	})
}

// TestReplaceTykVariables_ReusesResolvedSecrets shows that a secret already
// resolved for a request is not looked up again, so the URL rewrite host check
// compares against the value the rewrite used.
func TestReplaceTykVariables_ReusesResolvedSecrets(t *testing.T) {
	ts := StartTest(func(conf *config.Config) {
		conf.Secrets = map[string]string{"target": "http://store.example"}
	})
	defer ts.Close()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	t.Run("without resolved values the store is used", func(t *testing.T) {
		assert.Equal(t, "http://store.example/x", ts.Gw.ReplaceTykVariables(r, "$secret_conf.target/x", true))
	})

	t.Run("a resolved value is reused", func(t *testing.T) {
		resolved := map[string]string{"kv://secrets/target": "http://resolved.example"}
		withResolved := r.WithContext(context.WithValue(r.Context(), resolvedSecretsKey{}, resolved))
		assert.Equal(t, "http://resolved.example/x", ts.Gw.ReplaceTykVariables(withResolved, "$secret_conf.target/x", true))
	})

	t.Run("a lookup is recorded for the next pass", func(t *testing.T) {
		resolved := map[string]string{}
		withResolved := r.WithContext(context.WithValue(r.Context(), resolvedSecretsKey{}, resolved))
		_ = ts.Gw.ReplaceTykVariables(withResolved, "$secret_conf.target/$secret_conf.missing", true)
		assert.Equal(t, map[string]string{"kv://secrets/target": "http://store.example", "kv://secrets/missing": ""}, resolved)
	})
}

// processRewrite runs the URL rewrite middleware for one rule without loading
// the API, so it reaches rewrite_to values that the load-time check rejects.
// contextData, when set, stands in for the request context variables.
func processRewrite(t *testing.T, ts *Test, rewriteTo, target string, contextData map[string]interface{}) (int, *http.Request) {
	t.Helper()
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.VersionData.NotVersioned = true
	spec.VersionData.Versions = map[string]apidef.VersionInfo{"Default": {
		Name:             "Default",
		UseExtendedPaths: true,
		ExtendedPaths: apidef.ExtendedPathsSet{URLRewrite: []apidef.URLRewriteMeta{{
			Path: "/q", Method: http.MethodGet, MatchPattern: `^/q\?u=(.*)$`, RewriteTo: rewriteTo,
		}}},
	}}
	loader := APIDefinitionLoader{Gw: ts.Gw}
	spec.RxPaths = map[string][]URLSpec{}
	for name, v := range spec.VersionData.Versions {
		spec.RxPaths[name], _ = loader.getExtendedPathSpecs(v, spec, ts.Gw.GetConfig())
	}

	m := &URLRewriteMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: ts.Gw}}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if contextData != nil {
		ctxSetData(r, contextData)
	}
	_, code := m.ProcessRequest(httptest.NewRecorder(), r, nil)
	return code, r
}

// TestURLRewriteMiddleware_RequestValueCannotSetHost runs the middleware on
// rewrite_to values that the load-time check would reject, to show that the
// request-time check stops every form of host on its own.
func TestURLRewriteMiddleware_RequestValueCannotSetHost(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	process := func(t *testing.T, rewriteTo, target string) (int, *http.Request) {
		t.Helper()
		return processRewrite(t, ts, rewriteTo, target, nil)
	}

	for _, value := range []string{
		"http://rogue.example/x",
		"https://rogue.example/x",
		"HTTP://rogue.example/x",
		"ftp://rogue.example/x",
		"//rogue.example/x",
	} {
		t.Run(value, func(t *testing.T) {
			code, r := process(t, "$1", "/q?u="+value)
			assert.Equal(t, http.StatusBadRequest, code)
			assert.Nil(t, r.Context().Value(ctx.RetainHost))
		})
	}

	t.Run("context value with a full URL is escaped into a path", func(t *testing.T) {
		code, r := processRewrite(t, ts, "$tyk_context.headers_X_Target", "/q?u=x",
			map[string]interface{}{"headers_X_Target": "http://rogue.example/x"})
		assert.Equal(t, http.StatusOK, code)
		assert.Nil(t, r.Context().Value(ctx.RetainHost))
	})

	t.Run("still percent-encoded value is a path", func(t *testing.T) {
		code, r := process(t, "$1", "/q?u=http%3A%2F%2Frogue.example%2Fx")
		assert.Equal(t, http.StatusOK, code)
		assert.Nil(t, r.Context().Value(ctx.RetainHost))
	})

	for _, rewriteTo := range []string{
		"http://other.example/x",
		"https://other.example/x",
		"ws://chat.example/socket",
		"wss://chat.example/socket",
		"h2c://grpc.example/svc",
	} {
		t.Run("API manager wrote "+rewriteTo, func(t *testing.T) {
			code, r := process(t, rewriteTo, "/q?u=x")
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, true, r.Context().Value(ctx.RetainHost))
			target := ctxGetURLRewriteTarget(r)
			require.NotNil(t, target)
			want, _ := url.Parse(rewriteTo)
			assert.Equal(t, want.Host, target.Host)
		})
	}

	t.Run("API manager wrote a tyk:// loop", func(t *testing.T) {
		code, r := process(t, "tyk://self/x/$1", "/q?u=y")
		assert.Equal(t, http.StatusOK, code)
		target := ctxGetURLRewriteTarget(r)
		require.NotNil(t, target)
		assert.Equal(t, "tyk", target.Scheme)
	})
}
