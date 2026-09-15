package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

func TestMCPIngressNativeAndSyntheticSupport(t *testing.T) {
	for _, synthetic := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "synthetic"}[synthetic], func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.MarkAsMCP()
			spec.JSONRPCRouter = mcp.NewRouter()
			if synthetic {
				spec = buildSyntheticAdapterForRuntimeTest(t)
			}
			mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
			req.Header.Set(mcp.HeaderMethod, "tools/list")
			req.Header.Set(mcp.HeaderSessionID, "ignored")
			req.Header.Set(mcp.HeaderLastEventID, "ignored")
			rec := httptest.NewRecorder()
			err, status := mw.ProcessRequest(rec, req, nil)
			require.NoError(t, err)
			if synthetic {
				require.Equal(t, middleware.StatusRespond, status)
				require.Equal(t, http.StatusBadRequest, rec.Code)
				var response struct {
					ID    json.RawMessage
					Error struct {
						Code int
						Data struct{ Supported []string }
					}
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
				require.Equal(t, mcp.CodeUnsupportedProtocolVersion, response.Error.Code)
				require.Equal(t, mcp.LegacyProtocolVersions(), response.Error.Data.Supported)
				require.Equal(t, "9007199254740993", string(response.ID))
			} else {
				require.Equal(t, http.StatusOK, status)
				require.Empty(t, req.Header.Get(mcp.HeaderSessionID))
				require.Empty(t, req.Header.Get(mcp.HeaderLastEventID))
				require.NotNil(t, httpctx.GetJSONRPCRoutingState(req))
			}
		})
	}
}

func TestModernMethodRejectionRetainsValidation(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch,
		http.MethodHead, http.MethodConnect, http.MethodTrace,
	} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/mcp", nil)
			r.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
			ingress := mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", nil, nil)
			httpctx.SetMCPProtocolContext(r, ingress)
			w := httptest.NewRecorder()
			require.True(t, rejectModernMCPHTTPMethod(w, r))
			require.Equal(t, http.StatusMethodNotAllowed, ingress.Validation.HTTPStatus)
			require.Equal(t, http.StatusMethodNotAllowed, w.Code)
			require.Equal(t, http.MethodPost, w.Header().Get("Allow"))
			require.Equal(t, 0, ingress.Validation.Code, "plain HTTP errors do not invent a JSON-RPC wire code")
		})
	}
}

func TestModernMethodRejectionPreservesCORSOptionsAndLegacyVerbs(t *testing.T) {
	for _, test := range []struct {
		name    string
		method  string
		version string
	}{
		{name: "modern CORS preflight", method: http.MethodOptions, version: mcp.ModernProtocolVersion},
		{name: "legacy GET", method: http.MethodGet, version: mcp.LegacyFallbackProtocolVersion},
		{name: "legacy DELETE", method: http.MethodDelete, version: mcp.LegacyFallbackProtocolVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, "/mcp", nil)
			ingress := mcp.NewProtocolContext(test.version, "", nil, nil)
			httpctx.SetMCPProtocolContext(r, ingress)
			w := httptest.NewRecorder()
			require.False(t, rejectModernMCPHTTPMethod(w, r))
			require.Equal(t, 200, w.Code)
			require.False(t, ingress.Validation.Checked)
		})
	}
}

func TestJSONRPCIngressPreservesExactRequestIDs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		id   string
	}{
		{"zero", "0"},
		{"negative", "-1"},
		{"first adjacent large integer", "9007199254740992"},
		{"second adjacent large integer", "9007199254740993"},
		{"maximum int64", "9223372036854775807"},
		{"minimum int64", "-9223372036854775808"},
		{"string", `"request-9007199254740993"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":` + test.id + `,"method":"tools/list"}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{}}

			_, _, err := mw.readAndParseJSONRPC(rec, req)
			require.NoError(t, err)
			ingress := httpctx.GetMCPProtocolContext(req)
			require.NotNil(t, ingress)
			encoded, err := json.Marshal(ingress.Envelope.ID)
			require.NoError(t, err)
			require.Equal(t, test.id, string(encoded))
		})
	}
}

func TestJSONRPCContentTypeIsUnambiguousApplicationJSON(t *testing.T) {
	t.Parallel()
	mw := &JSONRPCMiddleware{}
	tests := []struct {
		name    string
		headers http.Header
		valid   bool
	}{
		{name: "bare", headers: http.Header{"Content-Type": {"application/json"}}, valid: true},
		{name: "parameterized", headers: http.Header{"Content-Type": {"application/json; charset=utf-8"}}, valid: true},
		{name: "quoted parameter", headers: http.Header{"Content-Type": {`application/json; charset="utf-8"`}}, valid: true},
		{name: "case insensitive media type", headers: http.Header{"Content-Type": {"Application/JSON"}}, valid: true},
		{name: "missing", headers: http.Header{}, valid: false},
		{name: "JSONP lookalike", headers: http.Header{"Content-Type": {"application/jsonp"}}, valid: false},
		{name: "JSON sequence", headers: http.Header{"Content-Type": {"application/json-seq"}}, valid: false},
		{name: "comma list", headers: http.Header{"Content-Type": {"application/json, text/plain"}}, valid: false},
		{name: "duplicate values", headers: http.Header{"Content-Type": {"application/json", "application/json"}}, valid: false},
		{name: "case variant duplicate keys", headers: http.Header{"Content-Type": {"application/json"}, "content-type": {"application/json"}}, valid: false},
		{name: "duplicate parameter", headers: http.Header{"Content-Type": {"application/json; charset=utf-8; charset=latin1"}}, valid: false},
		{name: "malformed parameter", headers: http.Header{"Content-Type": {"application/json; charset"}}, valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			r.Header = test.headers.Clone()
			require.Equal(t, test.valid, mw.validateJSONRPCRequest(r))
		})
	}
}

func TestPairedMCPProxyStrictIngressRunsBeforeInternalHop(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{
		Proxy: apidef.ProxyConfig{TargetURL: "tyk://rest-1/mcp"},
	}}
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	require.True(t, mw.EnabledForSpec())

	t.Run("valid request continues without public routing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set(mcp.HeaderProtocolVersion, "2025-03-26")
		rec := httptest.NewRecorder()

		err, status := mw.ProcessRequest(rec, req, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Nil(t, httpctx.GetJSONRPCRoutingState(req))
		require.Equal(t, "tools/list", ctxGetMCPMethod(req))
	})

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "JSONP", values: []string{"application/jsonp"}},
		{name: "JSON sequence", values: []string{"application/json-seq"}},
		{name: "comma list", values: []string{"application/json, text/plain"}},
		{name: "duplicate header", values: []string{"application/json", "application/json"}},
		{name: "duplicate parameter", values: []string{"application/json; charset=utf-8; charset=latin1"}},
		{name: "malformed parameter", values: []string{"application/json; charset"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
				`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			))
			req.Header[mcp.HeaderProtocolVersion] = []string{"2025-03-26"}
			req.Header[headerContentType] = test.values
			rec := httptest.NewRecorder()

			err, status := mw.ProcessRequest(rec, req, nil)
			require.NoError(t, err)
			require.Equal(t, middleware.StatusRespond, status)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Nil(t, httpctx.GetJSONRPCRoutingState(req))
			require.Empty(t, ctxGetMCPMethod(req))
		})
	}
}

func TestStrictJSONRPCIngressRejectsBeforeRouting(t *testing.T) {
	for _, synthetic := range []bool{false, true} {
		kind := map[bool]string{false: "native", true: "REST-as-MCP"}[synthetic]
		t.Run(kind, func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.MarkAsMCP()
			if synthetic {
				spec = buildSyntheticAdapterForRuntimeTest(t)
			}
			mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

			for _, test := range []struct {
				name        string
				contentType []string
				body        string
			}{
				{name: "JSONP", contentType: []string{"application/jsonp"}, body: `{"jsonrpc":"2.0","method":"tools/list"}`},
				{name: "comma list", contentType: []string{"application/json, text/plain"}, body: `{"jsonrpc":"2.0","method":"tools/list"}`},
				{name: "duplicate header", contentType: []string{"application/json", "application/json"}, body: `{"jsonrpc":"2.0","method":"tools/list"}`},
				{name: "duplicate envelope field", contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","method":"tools/list","method":"tools/call"}`},
				{name: "duplicate interpreted params field", contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"one","name":"two"}}`},
				{name: "duplicate modern metadata field", contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`},
			} {
				t.Run(test.name, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(test.body))
					req.Header[mcp.HeaderProtocolVersion] = []string{mcp.ModernProtocolVersion}
					req.Header[headerContentType] = test.contentType
					rec := httptest.NewRecorder()

					err, status := mw.ProcessRequest(rec, req, nil)
					require.NoError(t, err)
					require.Equal(t, middleware.StatusRespond, status)
					require.Equal(t, http.StatusBadRequest, rec.Code)
					require.Nil(t, httpctx.GetJSONRPCRoutingState(req))
					require.Empty(t, ctxGetMCPMethod(req))
					require.Empty(t, ctxGetMCPPrimitiveName(req))
				})
			}
		})
	}
}

func TestJSONRPCIngressReadLimitBoundary(t *testing.T) {
	t.Parallel()
	base := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	require.Less(t, len(base), mcpIngressReadLimit)
	for _, test := range []struct {
		name      string
		size      int
		wantError bool
	}{
		{"exact limit", mcpIngressReadLimit, false},
		{"one byte over", mcpIngressReadLimit + 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := base + strings.Repeat(" ", test.size-len(base))
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{}}

			_, raw, err := mw.readAndParseJSONRPC(rec, req)
			if test.wantError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "exceeds")
				require.Equal(t, http.StatusBadRequest, rec.Code)
				return
			}
			require.NoError(t, err)
			require.Len(t, raw, mcpIngressReadLimit)
		})
	}
}
