package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

// discoverConfirmsListLooksLegacyUpstream confirms 2026-07-28 on
// server/discover and answers tools/list with an error that, on its own,
// reads as a legacy server asking for a session.
func discoverConfirmsListLooksLegacyUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if !decodeMCPTestRequest(w, r, &req) {
			return
		}
		if req.Method == mcp.MethodServerDiscover {
			writeMCPTestJSON(t, w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
				"supportedVersions": []string{mcp.ModernProtocolVersion},
				"capabilities":      map[string]any{"tools": map[string]any{}},
			}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}`)); err != nil {
			t.Errorf("w.Write: %v", err)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestMCPAggregatorConfirmedProxyWithAFailingToolsListIsNotAVersionMismatch(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, discoverConfirmsListLooksLegacyUpstream(t).URL)
	hook := log.GetTestHook(t)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))

	require.Equal(t, http.StatusOK, res.code, res.body)
	assert.NotContains(t, res.body, "does not support MCP version")
	assert.Empty(t, mcpAggregatorToolCheckWarnings(hook, mcpAggregatorVersionUncheckedMsg, "github-mcp"), "server/discover confirmed the version")
	warnings := mcpAggregatorToolCheckWarnings(hook, mcpAggregatorToolsUncheckedMsg, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].Data["reason"], "Session not found")
}

func TestMCPAggregatorNarrowsAProxyWithMoreToolsThanTheCatalogueLimit(t *testing.T) {
	names := make([]string, mcpAggregatorMaxCatalogueTools+1)
	for i := range names {
		names[i] = fmt.Sprintf("tool_%05d", i)
	}
	big := newMCPRoutingUpstream(t, namedTools(names...)...)
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	ts, key := startMCPAggregatorSelectionTest(t, orders, big,
		aggregated("orders-mcp", "orders"),
		selecting("github-mcp", "github", "tool_00042", "tool_10000"),
	)

	assert.ElementsMatch(t, []string{"orders__list_orders", "github__tool_00042", "github__tool_10000"}, listedToolNames(t, ts, key),
		"the tool limit counts the selected tools, not every tool the proxy lists")
}

func TestMCPAggregatorWarnsAboutAMissingSelectedToolOncePerInterval(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts, key := startMCPAggregatorSelectionTest(t, orders, github,
		aggregated("orders-mcp", "orders"),
		selecting("github-mcp", "github", "list_issues", "delete_repo"),
	)
	hook := log.GetTestHook(t)

	for range 3 {
		assert.ElementsMatch(t, []string{"orders__list_orders", "github__list_issues"}, listedToolNames(t, ts, key))
	}

	warnings := mcpAggregatorMissingToolWarnings(hook)
	require.Len(t, warnings, 1, "the catalogue is not cached, so the warning would otherwise repeat on every tools/list")
	assert.Equal(t, "delete_repo", warnings[0].Data["tool"])
}

func TestMCPAggregatorWarningThrottle(t *testing.T) {
	var throttle mcpAggregatorWarningThrottle
	now := time.Now()

	assert.True(t, throttle.allow("a", now))
	assert.False(t, throttle.allow("a", now.Add(time.Minute)), "repeated within the interval")
	assert.True(t, throttle.allow("b", now.Add(time.Minute)), "another warning is independent")
	assert.True(t, throttle.allow("a", now.Add(mcpAggregatorRepeatedWarningInterval)), "logged again once the interval has passed")

	t.Run("bounded", func(t *testing.T) {
		var full mcpAggregatorWarningThrottle
		for i := range mcpAggregatorMaxThrottledWarnings {
			require.True(t, full.allow(fmt.Sprint(i), now))
		}
		assert.True(t, full.allow("new", now), "past the bound a warning is logged rather than remembered")
		assert.True(t, full.allow("new", now))
		assert.Len(t, full.logged, mcpAggregatorMaxThrottledWarnings)

		assert.True(t, full.allow("new", now.Add(mcpAggregatorRepeatedWarningInterval)), "expired entries make room again")
		assert.False(t, full.allow("new", now.Add(mcpAggregatorRepeatedWarningInterval+time.Second)))
	})
}
