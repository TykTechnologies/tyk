package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

func TestMCPDiscoveryJSONSSEParity(t *testing.T) {
	spec := buildMCPListFilterSSESpec("api", nil)
	req := httptest.NewRequest("POST", "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodServerDiscover})
	body := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"result":{"supportedVersions":["2099-01-01","2025-03-26","2026-07-28"],"capabilities":{"tools":{},"prompts":{}},"_meta":{"unknown":true},"resultType":"complete"}}`)
	for _, ses := range []*user.SessionState{nil, {AccessRights: map[string]user.AccessDefinition{"api": {JSONRPCMethodsAccessRights: user.AccessControlRules{Blocked: []string{"prompts/get"}}}}}} {
		global, credential := discoveryJSONRPCRuleSets(spec, ses)
		want, changed, _ := mcp.FilterDiscoveryBody(body, global, credential, spec)
		require.True(t, changed)
		hook := NewMCPListFilterSSEHook(spec, ses, req)
		require.NotNil(t, hook, "keyless discovery still intersects endpoint-supported versions")
		allowed, event := hook.FilterEvent(&SSEEvent{Event: "message", ID: "event-id", Data: []string{string(body)}})
		require.True(t, allowed)
		require.NotNil(t, event)
		require.JSONEq(t, string(want), strings.Join(event.Data, "\n"))
		require.Equal(t, "event-id", event.ID)
	}
	// Unrelated unfiltered streams must not acquire the filtering size guard.
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodToolsCall})
	require.Nil(t, NewMCPListFilterSSEHook(spec, nil, req))
}
