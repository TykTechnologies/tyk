package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// githubMCPProxyWithIPAccessControl is the github MCP proxy with an IP allow
// list and block list.
func githubMCPProxyWithIPAccessControl(upstreamURL string, allow, block []string) *APISpec {
	doc := mcpRuntimeDoc("github-mcp", upstreamURL)
	doc.GetTykExtension().Server.IPAccessControl = &oas.IPAccessControl{Enabled: true, Allow: allow, Block: block}
	return requireToken(mcpRuntimeOASSpec(doc, true))
}

// TestMCPAggregatorAppliesAggregatedProxyIPAccessControlToTheClientIP checks
// that an aggregated MCP proxy's IP allow and block lists see the address the
// aggregator resolved for its caller, from X-Real-IP, X-Forwarded-For or the
// connection, and not the address of a load balancer in front of the gateway.
// Test requests reach the gateway from 127.0.0.1.
func TestMCPAggregatorAppliesAggregatedProxyIPAccessControlToTheClientIP(t *testing.T) {
	const clientIP, otherIP = "203.0.113.7", "198.51.100.9"

	tests := []struct {
		name    string
		allow   []string
		block   []string
		header  http.Header
		allowed bool
	}{
		{name: "X-Forwarded-For in allow list", allow: []string{clientIP}, header: http.Header{"X-Forwarded-For": {clientIP + ", 10.0.0.1"}}, allowed: true},
		{name: "X-Forwarded-For outside allow list", allow: []string{clientIP}, header: http.Header{"X-Forwarded-For": {otherIP}}},
		{name: "X-Real-IP in allow list", allow: []string{clientIP}, header: http.Header{"X-Real-Ip": {clientIP}}, allowed: true},
		{name: "X-Real-IP outside allow list", allow: []string{clientIP}, header: http.Header{"X-Real-Ip": {otherIP}}},
		{name: "X-Forwarded-For in block list", block: []string{otherIP}, header: http.Header{"X-Forwarded-For": {otherIP}}},
		{name: "X-Forwarded-For outside block list", block: []string{otherIP}, header: http.Header{"X-Forwarded-For": {clientIP}}, allowed: true},
		{name: "connection address in allow list", allow: []string{"127.0.0.1"}, allowed: true},
		{name: "connection address outside allow list", allow: []string{clientIP}},
		{name: "connection address in block list", block: []string{"127.0.0.1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, github, _ := startMCPAggregatorRuntimeTest(t)
			ts.Gw.LoadAPI(
				githubMCPProxyWithIPAccessControl(github.URL, tc.allow, tc.block),
				companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
			)
			hook := log.GetTestHook(t)

			res := postModernToolsListWithHeader(t, ts, "/company-tools/", companyToolsKey(t, ts), tc.header)

			require.Equal(t, http.StatusOK, res.status, res.body)
			warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
			if tc.allowed {
				assert.Equal(t, []string{"github__create_issue", "github__search_repos"}, res.tools)
				assert.Empty(t, warnings)
				return
			}
			assert.Empty(t, res.tools)
			require.Len(t, warnings, 1)
			assert.Equal(t, "tools/list failed: tools/list failed with HTTP 403", warnings[0].Data["reason"])
		})
	}
}
