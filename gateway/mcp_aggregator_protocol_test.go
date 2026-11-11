package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// mcpVersionedUpstream is a remote MCP server that serves only the listed
// protocol versions. A request declaring any other version in its
// Mcp-Protocol-Version header is refused with HTTP 400, as the MCP SDKs do.
// It records the protocol declarations of every request it receives.
type mcpVersionedUpstream struct {
	*httptest.Server
	mu       sync.Mutex
	versions []string
	tools    []string
	requests []mcpObservedRequest
}

// mcpObservedRequest is what an upstream saw of one JSON-RPC request.
type mcpObservedRequest struct {
	Method         string
	HeaderVersion  string
	HeaderMethod   string
	MetaVersion    string
	InitializeWant string
}

func newMCPVersionedUpstream(t *testing.T, versions []string, tools ...string) *mcpVersionedUpstream {
	t.Helper()
	u := &mcpVersionedUpstream{versions: versions, tools: tools}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

// newLatestOnlyMCPUpstream serves only 2026-07-28.
func newLatestOnlyMCPUpstream(t *testing.T, tools ...string) *mcpVersionedUpstream {
	return newMCPVersionedUpstream(t, []string{mcp.ModernProtocolVersion}, tools...)
}

// newDualMCPUpstream serves 2026-07-28 and 2025-11-25.
func newDualMCPUpstream(t *testing.T, tools ...string) *mcpVersionedUpstream {
	return newMCPVersionedUpstream(t, []string{mcp.ModernProtocolVersion, "2025-11-25"}, tools...)
}

// newLegacyOnlyMCPUpstream serves only 2025-03-26.
func newLegacyOnlyMCPUpstream(t *testing.T, tools ...string) *mcpVersionedUpstream {
	return newMCPVersionedUpstream(t, []string{mcp.LegacyFallbackProtocolVersion}, tools...)
}

// setVersions changes the versions the upstream serves, as an upstream
// redeployed on another SDK would.
func (u *mcpVersionedUpstream) setVersions(versions ...string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.versions = versions
}

func (u *mcpVersionedUpstream) observed() []mcpObservedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]mcpObservedRequest(nil), u.requests...)
}

func (u *mcpVersionedUpstream) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
		Params struct {
			ProtocolVersion string                     `json:"protocolVersion"`
			Meta            map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var metaVersion string
	_ = json.Unmarshal(req.Params.Meta[mcp.MetaKeyProtocolVersion], &metaVersion)
	headerVersion := r.Header.Get(mcp.HeaderProtocolVersion)

	u.mu.Lock()
	u.requests = append(u.requests, mcpObservedRequest{
		Method:         req.Method,
		HeaderVersion:  headerVersion,
		HeaderMethod:   r.Header.Get(mcp.HeaderMethod),
		MetaVersion:    metaVersion,
		InitializeWant: req.Params.ProtocolVersion,
	})
	versions := append([]string(nil), u.versions...)
	tools := append([]string(nil), u.tools...)
	u.mu.Unlock()

	if headerVersion != "" && !slices.Contains(versions, headerVersion) {
		http.Error(w, fmt.Sprintf("Bad Request: Unsupported protocol version (supported versions: %s)", strings.Join(versions, ",")), http.StatusBadRequest)
		return
	}

	var result any
	switch req.Method {
	case mcp.MethodInitialize:
		negotiated := versions[0]
		if slices.Contains(versions, req.Params.ProtocolVersion) {
			negotiated = req.Params.ProtocolVersion
		}
		result = map[string]any{
			"protocolVersion": negotiated,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "versioned-upstream", "version": "1.0.0"},
		}
	case mcp.MethodServerDiscover:
		if !slices.Contains(versions, mcp.ModernProtocolVersion) {
			writeMCPTestJSONRPCError(w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
			return
		}
		result = map[string]any{
			"supportedVersions": versions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
		}
	case mcp.MethodToolsList:
		list := make([]map[string]any, 0, len(tools))
		for _, name := range tools {
			list = append(list, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
		}
		result = map[string]any{"tools": list}
	default:
		writeMCPTestJSONRPCError(w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func writeMCPTestJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

// mcpTestCall is one client JSON-RPC request to a gateway listen path.
type mcpTestCall struct {
	method string
	// version is sent in the Mcp-Protocol-Version header when set.
	version string
	// metaVersion is declared in params._meta when set.
	metaVersion string
	// initializeVersion is offered in initialize params.protocolVersion when set.
	initializeVersion string
	key               string
	sessionID         string
}

func (c mcpTestCall) body() string {
	params := map[string]any{}
	if c.metaVersion != "" {
		params["_meta"] = map[string]any{
			mcp.MetaKeyProtocolVersion:    c.metaVersion,
			mcp.MetaKeyClientCapabilities: map[string]any{},
		}
	}
	if c.initializeVersion != "" {
		params["protocolVersion"] = c.initializeVersion
		params["capabilities"] = map[string]any{}
		params["clientInfo"] = map[string]any{"name": "test", "version": "1"}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": c.method, "params": params})
	return string(body)
}

// modernCall declares 2026-07-28 in both the header and _meta.
func modernCall(method, key string) mcpTestCall {
	return mcpTestCall{method: method, version: mcp.ModernProtocolVersion, metaVersion: mcp.ModernProtocolVersion, key: key}
}

type mcpTestResponse struct {
	status int
	body   string
	header http.Header
	rpc    struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Requested string   `json:"requested"`
				Supported []string `json:"supported"`
			} `json:"data"`
		} `json:"error"`
	}
}

func postMCPTestCall(t *testing.T, ts *Test, listenPath string, call mcpTestCall) mcpTestResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+listenPath, strings.NewReader(call.body()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if call.version != "" {
		req.Header.Set(mcp.HeaderProtocolVersion, call.version)
		if call.version == mcp.ModernProtocolVersion {
			req.Header.Set(mcp.HeaderMethod, call.method)
		}
	}
	if call.key != "" {
		req.Header.Set("Authorization", call.key)
	}
	if call.sessionID != "" {
		req.Header.Set(mcp.HeaderSessionID, call.sessionID)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	out := mcpTestResponse{status: resp.StatusCode, body: string(raw), header: resp.Header}
	message := raw
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		if event, err := mcpAggregatorEventStreamResponse(raw); err == nil {
			message = event
		}
	}
	_ = json.Unmarshal(message, &out.rpc)
	return out
}

// assertUnsupportedMCPVersion checks the gateway's unsupported protocol
// version rejection and that it names 2026-07-28 as the only supported version.
func assertUnsupportedMCPVersion(t *testing.T, res mcpTestResponse, requested string) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcp.CodeUnsupportedProtocolVersion, res.rpc.Error.Code, res.body)
	assert.Equal(t, "unsupported protocol version", res.rpc.Error.Message)
	assert.Equal(t, requested, res.rpc.Error.Data.Requested)
	assert.Equal(t, []string{mcp.ModernProtocolVersion}, res.rpc.Error.Data.Supported)
	assert.NotContains(t, res.body, "__", "a rejected request carries no aggregated tool")
}

// startMCPAggregatorProtocolTest loads company-tools over orders-mcp (an
// API-to-MCP proxy) and github-mcp (a remote MCP proxy over github).
func startMCPAggregatorProtocolTest(t *testing.T, github *mcpVersionedUpstream) (*Test, string) {
	t.Helper()
	ts, _, ordersBackend := startMCPAggregatorRuntimeTest(t)
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	return ts, companyToolsKey(t, ts)
}

func TestMCPAggregatorServesRequestsDeclaringTheLatestVersion(t *testing.T) {
	ts, key := startMCPAggregatorProtocolTest(t, newDualMCPUpstream(t, "list_issues"))

	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))

	require.Equal(t, http.StatusOK, res.status, res.body)
	require.Nil(t, res.rpc.Error, res.body)
	assert.Contains(t, res.body, `"github__list_issues"`)
	assert.Contains(t, res.body, `"orders__list_orders"`)
}

func TestMCPAggregatorRejectsOlderDeclaredVersions(t *testing.T) {
	ts, key := startMCPAggregatorProtocolTest(t, newDualMCPUpstream(t, "list_issues"))

	for name, call := range map[string]mcpTestCall{
		"header and _meta":   {method: mcp.MethodToolsList, version: "2025-11-25", metaVersion: "2025-11-25", key: key},
		"header only":        {method: mcp.MethodToolsList, version: "2025-11-25", key: key},
		"_meta only":         {method: mcp.MethodToolsList, metaVersion: "2025-11-25", key: key},
		"initialize offer":   {method: mcp.MethodInitialize, initializeVersion: "2025-11-25", key: key},
		"initialize+header":  {method: mcp.MethodInitialize, version: "2025-11-25", initializeVersion: "2025-11-25", key: key},
		"without credential": {method: mcp.MethodToolsList, version: "2025-11-25", metaVersion: "2025-11-25"},
	} {
		t.Run(name, func(t *testing.T) {
			assertUnsupportedMCPVersion(t, postMCPTestCall(t, ts, "/company-tools/", call), "2025-11-25")
		})
	}
}

func TestMCPAggregatorRejectsLegacyHeaderlessRequests(t *testing.T) {
	ts, key := startMCPAggregatorProtocolTest(t, newDualMCPUpstream(t, "list_issues"))

	for name, call := range map[string]mcpTestCall{
		"tools/list":          {method: mcp.MethodToolsList, key: key},
		"initialize":          {method: mcp.MethodInitialize, initializeVersion: mcp.LegacyFallbackProtocolVersion, key: key},
		"established session": {method: mcp.MethodToolsList, key: key, sessionID: "legacy-session"},
		"without credential":  {method: mcp.MethodToolsList},
	} {
		t.Run(name, func(t *testing.T) {
			assertUnsupportedMCPVersion(t, postMCPTestCall(t, ts, "/company-tools/", call), mcp.LegacyFallbackProtocolVersion)
		})
	}
}

func TestMCPAggregatorVersionRestrictionLeavesOtherMCPProxiesAlone(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, _ := startMCPAggregatorProtocolTest(t, github)
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{
			"github-mcp": {APIID: "github-mcp", APIName: "github-mcp"},
			"orders-mcp": {APIID: "orders-mcp", APIName: "orders-mcp"},
		}
	})

	t.Run("remote MCP proxy on 2025-11-25", func(t *testing.T) {
		res := postMCPTestCall(t, ts, "/github-mcp/", mcpTestCall{method: mcp.MethodToolsList, version: "2025-11-25", key: key})
		require.Equal(t, http.StatusOK, res.status, res.body)
		assert.Contains(t, res.body, `"list_issues"`)
		observed := github.observed()
		assert.Equal(t, "2025-11-25", observed[len(observed)-1].HeaderVersion, "the proxy forwards the client's version unchanged")
	})
	t.Run("remote MCP proxy headerless", func(t *testing.T) {
		res := postMCPTestCall(t, ts, "/github-mcp/", mcpTestCall{method: mcp.MethodToolsList, key: key})
		require.Equal(t, http.StatusOK, res.status, res.body)
		assert.Contains(t, res.body, `"list_issues"`)
	})
	t.Run("API-to-MCP proxy initialize on 2025-11-25", func(t *testing.T) {
		res := postMCPTestCall(t, ts, "/orders-mcp/", mcpTestCall{method: mcp.MethodInitialize, version: "2025-11-25", initializeVersion: "2025-11-25", key: key})
		require.Equal(t, http.StatusOK, res.status, res.body)
		assert.JSONEq(t, `"2025-11-25"`, string(mcpTestResultField(t, res, "protocolVersion")))
	})
	t.Run("API-to-MCP proxy headerless initialize", func(t *testing.T) {
		res := postMCPTestCall(t, ts, "/orders-mcp/", mcpTestCall{method: mcp.MethodInitialize, initializeVersion: mcp.LegacyFallbackProtocolVersion, key: key})
		require.Equal(t, http.StatusOK, res.status, res.body)
		assert.JSONEq(t, `"2025-03-26"`, string(mcpTestResultField(t, res, "protocolVersion")))
	})
}

func mcpTestResultField(t *testing.T, res mcpTestResponse, field string) json.RawMessage {
	t.Helper()
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(res.rpc.Result, &result), res.body)
	return result[field]
}

func TestMCPAggregatorAdvertisesOnlyTheLatestSupportedVersion(t *testing.T) {
	assert.Equal(t, []string{mcp.ModernProtocolVersion}, companyToolsRuntimeSpec(aggregated("github-mcp", "github")).SupportedProtocolVersions())
	assert.Equal(t, mcp.ServedProtocolVersions(), githubMCPProxyRuntimeSpec("http://github.invalid").SupportedProtocolVersions())
}
