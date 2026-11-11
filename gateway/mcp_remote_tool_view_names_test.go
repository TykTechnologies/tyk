package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/user"
)

const (
	upstreamGitHubCreateIssue = `{"name":"create_issue","title":"Create issue","description":"Create an issue","inputSchema":{"type":"object","properties":{"repo":{"type":"string"},"title":{"type":"string"}},"required":["repo","title"]},"annotations":{"idempotentHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1}}`
	upstreamGitHubListIssues  = `{"name":"list_issues","description":"List issues in a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}},"required":["repo"]},"annotations":{"readOnlyHint":true}}`
	upstreamGitHubOpenIssue   = `{"name":"open_issue","description":"The upstream's own open_issue","inputSchema":{"type":"object"}}`
	upstreamRemoveRepo        = `{"name":"remove_repo","description":"Upstream remove_repo","inputSchema":{"type":"object"}}`
	upstreamUpdateRepo        = `{"name":"update_repo","description":"Upstream update_repo","inputSchema":{"type":"object"}}`

	openIssueDescription = "Open a new issue in a repository. Requires the repository name and a title."
)

func describedRename(source, name, description string) oas.TykMCPServerPrimitive {
	return oas.TykMCPServerPrimitive{Source: oas.TykMCPServerSource{ToolName: source}, Name: name, Description: description}
}

// openIssueOverride renames create_issue to open_issue with a new
// description and marks it idempotent.
func openIssueOverride() oas.TykMCPServerPrimitive {
	primitive := describedRename("create_issue", "open_issue", openIssueDescription)
	primitive.Annotations = &oas.DerivedToolAnnotations{IdempotentHint: boolPtr(true)}
	return primitive
}

func swapOverrides() []oas.TykMCPServerPrimitive {
	return []oas.TykMCPServerPrimitive{renameOverride("remove_repo", "delete_repo"), renameOverride("update_repo", "remove_repo")}
}

func toolField(t *testing.T, tool json.RawMessage, field string) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(tool, &fields))
	return fields[field]
}

func TestRemoteMCPToolView_ToolsListRenamesAndDescriptions(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, _, _ := startRemoteMCPProxyWithView(t, "remote-mcp-renames-"+transport, transport == "sse",
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

			status, header, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, status, string(body))
			assert.Equal(t, transport == "sse", strings.HasPrefix(header.Get("Content-Type"), "text/event-stream"))
			tools, names, result := listedTools(t, body)

			t.Run("open_issue listed with the new description, create_issue not listed", func(t *testing.T) {
				assert.Equal(t, []string{"open_issue", "list_issues"}, names)
				assert.JSONEq(t, `"`+openIssueDescription+`"`, string(toolField(t, tools["open_issue"], "description")))
				assert.NotContains(t, string(body), `"create_issue"`)
			})
			t.Run("list_issues unchanged", func(t *testing.T) {
				assert.JSONEq(t, upstreamGitHubListIssues, string(tools["list_issues"]))
			})
			t.Run("open_issue inputSchema equals the upstream create_issue inputSchema", func(t *testing.T) {
				assert.JSONEq(t, string(toolField(t, json.RawMessage(upstreamGitHubCreateIssue), "inputSchema")), string(toolField(t, tools["open_issue"], "inputSchema")))
			})
			t.Run("renamed tool carries the idempotentHint override; other fields kept", func(t *testing.T) {
				assert.JSONEq(t, `{"name":"open_issue","title":"Create issue","description":"`+openIssueDescription+`","inputSchema":{"type":"object","properties":{"repo":{"type":"string"},"title":{"type":"string"}},"required":["repo","title"]},"annotations":{"idempotentHint":true,"x-vendor":"kept"},"_meta":{"io.example/x":1}}`, string(tools["open_issue"]))
				assert.JSONEq(t, `{"upstream":"kept"}`, string(result["_meta"]))
			})
		})
	}
}

func TestRemoteMCPToolView_ToolsListAfterASwap(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, _, _ := startRemoteMCPProxyWithView(t, "remote-mcp-swap-"+transport, transport == "sse", swapOverrides(),
				upstreamRemoveRepo, upstreamUpdateRepo, upstreamListRepos)

			_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
			tools, names, _ := listedTools(t, body)
			assert.Equal(t, []string{"delete_repo", "remove_repo", "list_repos"}, names)
			assert.JSONEq(t, `{"name":"delete_repo","description":"Upstream remove_repo","inputSchema":{"type":"object"}}`, string(tools["delete_repo"]))
			assert.JSONEq(t, `{"name":"remove_repo","description":"Upstream update_repo","inputSchema":{"type":"object"}}`, string(tools["remove_repo"]))
			assert.NotContains(t, string(body), `"update_repo"`)
		})
	}
}

func TestRemoteMCPToolView_RenamedSourceMissingUpstream(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			apiID := "remote-mcp-renamed-missing-" + transport
			ts, fake, _ := startRemoteMCPProxyWithView(t, apiID, transport == "sse",
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
			logs := recordRemoteMCPLogs(t, apiID)
			fake.setTools(upstreamGitHubListIssues)

			_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
			_, names, _ := listedTools(t, body)
			assert.Equal(t, []string{"list_issues"}, names, "open_issue is absent")
			assert.NotNil(t, logs.find(logrus.WarnLevel, "not in the upstream tool list", "source_tool=create_issue"),
				"a warning names create_issue as missing from the upstream")
		})
	}
}

func TestRemoteMCPToolView_UpstreamToolNamedLikeAnOverrideIsHidden(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			apiID := "remote-mcp-drift-collision-" + transport
			ts, fake, _ := startRemoteMCPProxyWithView(t, apiID, transport == "sse",
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
			logs := recordRemoteMCPLogs(t, apiID)
			fake.setTools(upstreamGitHubOpenIssue, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

			for range 2 {
				_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
				tools, names, _ := listedTools(t, body)
				assert.Equal(t, []string{"open_issue", "list_issues"}, names, "exactly one open_issue")
				assert.JSONEq(t, `"`+openIssueDescription+`"`, string(toolField(t, tools["open_issue"], "description")),
					"the listed open_issue is the overridden create_issue")
				assert.NotContains(t, string(body), "The upstream's own open_issue")
			}
			assert.NotNil(t, logs.find(logrus.WarnLevel, "hidden", "upstream_tool=open_issue"), "a warning names the upstream's open_issue as hidden")
			assert.Equal(t, 1, logs.count(logrus.WarnLevel, "upstream_tool=open_issue"), "the warning is rate limited")
		})
	}
}

func TestRemoteMCPToolView_AccessRulesApplyToExposedNames(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			t.Run("blocking open_issue hides the renamed tool", func(t *testing.T) {
				ts, _, spec := startRemoteMCPProxyWithView(t, "remote-mcp-acl-open-issue-"+transport, transport == "sse",
					[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
				key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"open_issue"}})

				status, _, body := remoteMCPRequest(t, ts, key, "tools/list", `{}`)
				require.Equal(t, http.StatusOK, status, string(body))
				_, names, _ := listedTools(t, body)
				assert.Equal(t, []string{"list_issues"}, names)
			})

			t.Run("blocking the upstream name keeps the renamed tool", func(t *testing.T) {
				ts, _, spec := startRemoteMCPProxyWithView(t, "remote-mcp-acl-renamed-"+transport, transport == "sse",
					[]oas.TykMCPServerPrimitive{renameOverride("delete_repo", "remove_repository")}, upstreamDeleteRepo, upstreamListRepos)
				key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"delete_repo"}})

				_, _, body := remoteMCPRequest(t, ts, key, "tools/list", `{}`)
				_, names, _ := listedTools(t, body)
				assert.Equal(t, []string{"remove_repository", "list_repos"}, names)
			})

			t.Run("after a swap, blocking remove_repo hides the tool exposed as remove_repo", func(t *testing.T) {
				ts, _, spec := startRemoteMCPProxyWithView(t, "remote-mcp-acl-swap-"+transport, transport == "sse", swapOverrides(),
					upstreamRemoveRepo, upstreamUpdateRepo)
				key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"remove_repo"}})

				_, _, body := remoteMCPRequest(t, ts, key, "tools/list", `{}`)
				tools, names, _ := listedTools(t, body)
				assert.Equal(t, []string{"delete_repo"}, names)
				assert.JSONEq(t, `"Upstream remove_repo"`, string(toolField(t, tools["delete_repo"], "description")))
			})
		})
	}
}
