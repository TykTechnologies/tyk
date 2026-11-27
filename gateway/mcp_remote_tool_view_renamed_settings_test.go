package gateway

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func blockedMCPTool() *oas.MCPPrimitive {
	return &oas.MCPPrimitive{Operation: oas.Operation{Block: &oas.Allowance{Enabled: true}}}
}

func withMCPToolSettings(tools oas.MCPPrimitives) func(*APISpec) {
	return func(spec *APISpec) {
		spec.OAS.GetTykExtension().Middleware = &oas.Middleware{McpTools: tools}
	}
}

func TestRemoteMCPToolView_SettingsForRenamedAwayTools(t *testing.T) {
	t.Run("a middleware.mcpTools entry for a renamed source tool is reported", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-renamed-settings"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()},
			withMCPToolSettings(oas.MCPPrimitives{
				"create_issue": blockedMCPTool(),
				"open_issue":   {},
				"list_issues":  {},
				"create_*":     blockedMCPTool(),
			}))
		require.NotNil(t, spec.MCPToolView())

		warning := logs.find(logrus.WarnLevel, "no longer applies", "tool=create_issue")
		require.NotNil(t, warning, "the stale setting must be reported")
		assert.Contains(t, warning.text, "exposed_name=open_issue")
		assert.Contains(t, warning.text, "setting=middleware.mcpTools")
		assert.Equal(t, 1, logs.count(logrus.WarnLevel, "no longer applies"), "settings for exposed names, untouched tools and wildcards are not reported")
	})

	t.Run("a chained rename reports the entry whose name another tool took", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-renamed-settings-chain"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, upstreamRemoveRepo, upstreamUpdateRepo)

		// remove_repo -> delete_repo, update_repo -> remove_repo.
		loadRemoteMCPProxy(t, ts, apiID, upstream.URL, swapOverrides(),
			withMCPToolSettings(oas.MCPPrimitives{"remove_repo": {}, "update_repo": {}, "delete_repo": {}}))

		assert.NotNil(t, logs.find(logrus.WarnLevel, "no longer applies", "tool=update_repo", "exposed_name=remove_repo"))
		taken := logs.find(logrus.WarnLevel, "now applies to upstream tool", "tool=remove_repo")
		require.NotNil(t, taken, "the remove_repo entry now governs the upstream update_repo")
		assert.Contains(t, taken.text, "upstream_tool=update_repo")
		assert.Nil(t, logs.find(logrus.WarnLevel, "tool=delete_repo"), "delete_repo was never an upstream tool name")
	})

	t.Run("a swap reports both entries", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-renamed-settings-swap"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, upstreamDeleteRepo, upstreamRemoveRepo)

		loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			renameOverride("delete_repo", "remove_repo"),
			renameOverride("remove_repo", "delete_repo"),
		}, withMCPToolSettings(oas.MCPPrimitives{"delete_repo": blockedMCPTool(), "remove_repo": {}}))

		assert.NotNil(t, logs.find(logrus.WarnLevel, "now applies to upstream tool", "tool=delete_repo", "upstream_tool=remove_repo"))
		assert.NotNil(t, logs.find(logrus.WarnLevel, "now applies to upstream tool", "tool=remove_repo", "upstream_tool=delete_repo"))
		assert.Nil(t, logs.find(logrus.WarnLevel, "no longer applies"), "nothing is renamed away in a swap")
	})

	t.Run("enforcement is unchanged", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		fake, upstream := newFakeRemoteMCPServer(t, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

		loadRemoteMCPProxy(t, ts, "remote-mcp-renamed-settings-enforcement", upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()},
			withMCPToolSettings(oas.MCPPrimitives{"create_issue": blockedMCPTool()}))

		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash"}}`, nil)
		assert.Equal(t, http.StatusOK, status, string(body), "blocking the source name does not block the exposed name")
		assert.Equal(t, []string{"create_issue"}, fake.calledTools())
	})
}
