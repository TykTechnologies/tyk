package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// Committed stub engine fixtures from the wafjs host skeleton bead. The
// ruleset carries the CRS pin the middleware requires.
var (
	wafStubEngineDir   = filepath.Join("..", "internal", "wafjs", "testdata")
	wafStubEnginePath  = filepath.Join(wafStubEngineDir, "engine.json")
	wafStubRulesetPath = filepath.Join(wafStubEngineDir, "ruleset.json")
)

// Engine programs for generated stub artifacts. Each defines the single ABI
// entry point; the finding shape must be exactly the documented one.
const (
	wafBlockEngineJS = `globalThis.wafjsInspect = function (tx, request) {
	return {
		verdict: "block",
		anomaly_score: 7,
		matched_rule_ids: ["942100"],
		inspection_scope: ["args"],
		body_inspected: false,
		skip_reason: "",
		unsupported_features: []
	};
};`

	wafThrowEngineJS = `globalThis.wafjsInspect = function (tx, request) {
	throw new Error("stub engine failure");
};`
)

// wafWriteArtifacts writes a valid engine/ruleset artifact pair carrying the
// middleware's CRS pin into a fresh temp directory.
func wafWriteArtifacts(t *testing.T, engineJS string) (enginePath, rulesetPath string) {
	t.Helper()
	dir := t.TempDir()

	engine := map[string]any{
		"schema_version": 1,
		"kind":           "wafjs-engine",
		"version":        "1",
		"javascript":     engineJS,
	}
	ruleset := map[string]any{
		"schema_version":      1,
		"kind":                "wafjs-ruleset",
		"version":             "1",
		"crs_release":         wafCRSRelease,
		"crs_manifest_sha256": wafCRSManifestSHA256,
		"rules":               []any{},
	}

	enginePath = filepath.Join(dir, "engine.json")
	rulesetPath = filepath.Join(dir, "ruleset.json")
	for name, artifact := range map[string]map[string]any{
		enginePath:  engine,
		rulesetPath: ruleset,
	} {
		raw, err := json.Marshal(artifact)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(name, raw, 0o600))
	}
	return enginePath, rulesetPath
}

// wafEnableGlobal turns on the global WAF gate against the given artifacts.
func wafEnableGlobal(c *config.Config, enginePath, rulesetPath string) {
	c.WAF.Enabled = true
	c.WAF.EnginePath = enginePath
	c.WAF.RulesetPath = rulesetPath
	c.WAF.BodyLimit = wafRequestBodyLimit
}

// wafLoadAPI loads one keyless API whose upstream is the dynamic echo
// handler registered under upstreamKey.
func wafLoadAPI(ts *Test, id, listenPath, upstreamKey string, waf apidef.WAFConfig, extra func(spec *APISpec)) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = id
		spec.Name = id
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = TestHttpAny + "/" + upstreamKey
		spec.Proxy.StripListenPath = true
		spec.WAF = waf
		if extra != nil {
			extra(spec)
		}
	})
}

// wafRegisterEcho registers an echo upstream under key that records every
// received request through the corpus upstream recorder.
func wafRegisterEcho(ts *Test, rec *wafUpstreamRecorder, key string) {
	ts.AddDynamicHandler(key, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.record(r.URL.Path, body)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			return
		}
	})
}

// wafUpstreamHits returns how many requests the upstream received.
func wafUpstreamHits(rec *wafUpstreamRecorder) int {
	hits, _, _, _ := rec.snapshot()
	return hits
}

func TestWAFMiddlewareEnforcement(t *testing.T) {
	t.Run("block verdict returns 403 and never reaches upstream", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-block-upstream")
		wafLoadAPI(ts, "waf-block", "/waf-block-api", "waf-block-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeBlock,
		}, nil)

		resp, err := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/waf-block-api/",
			Code:   http.StatusForbidden,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.NotContains(t, string(body), "942100", "rule IDs must never enter the client response")
		assert.NotContains(t, string(body), "anomaly", "scores must never enter the client response")
		assert.Zero(t, wafUpstreamHits(rec), "a blocked request must never reach upstream")
	})

	t.Run("audit passes through with the byte-for-byte restored body", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-audit-upstream")
		wafLoadAPI(ts, "waf-audit", "/waf-audit-api", "waf-audit-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeAudit,
		}, nil)

		// Binary-unsafe body: NUL bytes and invalid UTF-8 must survive the
		// round trip unchanged even though the engine blocked the request.
		body := []byte{0x00, 0x01, 0xff, 0xfe, 'a', 0x00, 0x7f, 'z', 0x80, 0xc3, 0x28}
		resp, err := ts.Run(t, test.TestCase{
			Method:  http.MethodPost,
			Path:    "/waf-audit-api/",
			Data:    body,
			Headers: map[string]string{"Content-Type": "application/octet-stream"},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)

		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, body, respBody, "audit mode must return the upstream body unchanged")

		hits, _, size, sha := rec.snapshot()
		assert.Equal(t, 1, hits, "audit mode must reach upstream exactly once")
		assert.Equal(t, len(body), size, "the upstream must receive the original body size")
		assert.Equal(t, wafCorpusSHA256Hex(body), sha, "the upstream must receive the original bytes byte-for-byte")
	})

	t.Run("per-API disabled flag bypasses inspection", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-api-off-upstream")
		wafLoadAPI(ts, "waf-api-off", "/waf-api-off", "waf-api-off-upstream", apidef.WAFConfig{
			Enabled: false,
			Mode:    apidef.WAFModeBlock,
		}, nil)

		_, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-api-off/", Code: http.StatusOK})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "a disabled per-API flag must bypass the blocking engine")
	})

	t.Run("global gate off bypasses inspection", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) {
			c.WAF.Enabled = false
			c.WAF.EnginePath = enginePath
			c.WAF.RulesetPath = rulesetPath
		})
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-global-off-upstream")
		wafLoadAPI(ts, "waf-global-off", "/waf-global-off", "waf-global-off-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeBlock,
		}, nil)

		_, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-global-off/", Code: http.StatusOK})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "a disabled global gate must bypass the blocking engine")
	})

	t.Run("fail-open continues upstream on engine failure", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafThrowEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-fail-open-upstream")
		wafLoadAPI(ts, "waf-fail-open", "/waf-fail-open", "waf-fail-open-upstream", apidef.WAFConfig{
			Enabled:    true,
			Mode:       apidef.WAFModeBlock,
			FailClosed: false,
		}, nil)

		_, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-fail-open/", Code: http.StatusOK})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "fail-open must continue upstream on an engine failure")
	})

	t.Run("fail-closed returns 503 without rule details on engine failure", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafThrowEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-fail-closed-upstream")
		wafLoadAPI(ts, "waf-fail-closed", "/waf-fail-closed", "waf-fail-closed-upstream", apidef.WAFConfig{
			Enabled:    true,
			Mode:       apidef.WAFModeBlock,
			FailClosed: true,
		}, nil)

		resp, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-fail-closed/", Code: http.StatusServiceUnavailable})
		require.NoError(t, err)
		require.NotNil(t, resp)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.NotContains(t, string(body), "stub engine failure", "internal failure details must never enter the client response")
		assert.NotContains(t, string(body), "942100", "rule IDs must never enter the client response")
		assert.Zero(t, wafUpstreamHits(rec), "a fail-closed rejection must never reach upstream")
	})

	t.Run("missing engine artifacts apply the failure policy", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing-engine.json")
		ts := StartTest(func(c *config.Config) {
			wafEnableGlobal(c, missing, missing)
		})
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-no-artifacts-upstream")

		// One load call: each LoadAPI reload replaces the loaded set.
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.APIID = "waf-no-artifacts-open"
				spec.Name = "waf-no-artifacts-open"
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/waf-no-artifacts-open"
				spec.Proxy.TargetURL = TestHttpAny + "/waf-no-artifacts-upstream"
				spec.Proxy.StripListenPath = true
				spec.WAF = apidef.WAFConfig{Enabled: true, Mode: apidef.WAFModeBlock, FailClosed: false}
			},
			func(spec *APISpec) {
				spec.APIID = "waf-no-artifacts-closed"
				spec.Name = "waf-no-artifacts-closed"
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/waf-no-artifacts-closed"
				spec.Proxy.TargetURL = TestHttpAny + "/waf-no-artifacts-upstream"
				spec.Proxy.StripListenPath = true
				spec.WAF = apidef.WAFConfig{Enabled: true, Mode: apidef.WAFModeBlock, FailClosed: true}
			},
		)

		_, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-no-artifacts-open/", Code: http.StatusOK})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "an unbuilt engine must fail open when the policy says so")

		resp, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-no-artifacts-closed/", Code: http.StatusServiceUnavailable})
		require.NoError(t, err)
		require.NotNil(t, resp)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(body), "artifact", "internal failure details must never enter the client response")
		assert.Equal(t, 1, wafUpstreamHits(rec), "only the fail-open request may reach upstream")
	})

	t.Run("committed stub engine passes requests through", func(t *testing.T) {
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, wafStubEnginePath, wafStubRulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-stub-upstream")
		wafLoadAPI(ts, "waf-stub", "/waf-stub-api", "waf-stub-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeBlock,
		}, nil)

		_, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-stub-api/", Code: http.StatusOK})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "the committed allow stub must pass the request through")
	})

	t.Run("JSON-RPC APIs are skipped", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) { wafEnableGlobal(c, enginePath, rulesetPath) })
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-jsonrpc-upstream")

		// A JSON-RPC 2.0 API that is not MCP: the full chain runs, the WAF
		// skips it, and even the blocking engine never inspects it.
		wafLoadAPI(ts, "waf-jsonrpc", "/waf-jsonrpc-api", "waf-jsonrpc-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeBlock,
		}, func(spec *APISpec) {
			spec.JsonRpcVersion = apidef.JsonRPC20
		})

		_, err := ts.Run(t, test.TestCase{
			Method:  http.MethodPost,
			Path:    "/waf-jsonrpc-api/",
			Data:    `{"jsonrpc":"2.0","method":"subtract","params":[42,23],"id":1}`,
			Headers: map[string]string{"Content-Type": "application/json"},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)
		assert.Equal(t, 1, wafUpstreamHits(rec), "a JSON-RPC API must bypass the blocking engine")
	})

	t.Run("enforcement is independent of EnableJSVM", func(t *testing.T) {
		enginePath, rulesetPath := wafWriteArtifacts(t, wafBlockEngineJS)
		ts := StartTest(func(c *config.Config) {
			wafEnableGlobal(c, enginePath, rulesetPath)
			// The test harness force-enables JSVM; the WAF must not depend
			// on it in either direction.
			c.EnableJSVM = false
		})
		defer ts.Close()

		rec := &wafUpstreamRecorder{}
		wafRegisterEcho(ts, rec, "waf-nojsvm-upstream")
		wafLoadAPI(ts, "waf-nojsvm", "/waf-nojsvm-api", "waf-nojsvm-upstream", apidef.WAFConfig{
			Enabled: true,
			Mode:    apidef.WAFModeBlock,
		}, nil)

		resp, err := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/waf-nojsvm-api/", Code: http.StatusForbidden})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Zero(t, wafUpstreamHits(rec), "WAF enforcement must work with EnableJSVM off")

		// The harness boots every other subtest with EnableJSVM=true (set
		// in gateway/testutil.go), and those subtests enforce identically,
		// covering the opposite direction.
		assert.False(t, ts.Gw.GetConfig().EnableJSVM)
	})
}

func TestWAFMiddlewareEnabledForSpec(t *testing.T) {
	gw := &Gateway{}
	gw.SetConfig(config.Config{WAF: config.WAFConfig{Enabled: true}})

	enabledFor := func(spec *APISpec) bool {
		mw := &WAFMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
		return mw.EnabledForSpec()
	}

	mcpSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "waf-mcp"
		spec.MarkAsMCP()
		spec.WAF = apidef.WAFConfig{Enabled: true, Mode: apidef.WAFModeBlock}
	})[0]
	assert.False(t, enabledFor(mcpSpec), "MCP APIs must be excluded from WAF inspection")

	jsonrpcSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "waf-jsonrpc-spec"
		spec.JsonRpcVersion = apidef.JsonRPC20
		spec.WAF = apidef.WAFConfig{Enabled: true, Mode: apidef.WAFModeBlock}
	})[0]
	assert.False(t, enabledFor(jsonrpcSpec), "JSON-RPC APIs must be excluded from WAF inspection")

	restSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "waf-rest-spec"
		spec.WAF = apidef.WAFConfig{Enabled: true, Mode: apidef.WAFModeBlock}
	})[0]
	assert.True(t, enabledFor(restSpec), "a REST API with both flags on must enable WAF inspection")

	perAPIOffSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "waf-rest-off"
		spec.WAF = apidef.WAFConfig{Enabled: false, Mode: apidef.WAFModeBlock}
	})[0]
	assert.False(t, enabledFor(perAPIOffSpec), "a REST API with the per-API flag off must not enable WAF inspection")

	gw.SetConfig(config.Config{WAF: config.WAFConfig{Enabled: false}})
	assert.False(t, enabledFor(restSpec), "a disabled global flag must not enable WAF inspection")
}
