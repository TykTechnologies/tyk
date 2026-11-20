package gateway

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// remoteMCPToolsCall sends a tools/call with the given params and extra
// headers through the gateway and returns the JSON-RPC response.
func remoteMCPToolsCall(t *testing.T, ts *Test, key, params string, headers map[string]string) (int, []byte) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":` + params + `}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+remoteMCPListenPath, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, "2025-06-18")
	if key != "" {
		req.Header.Set("Authorization", key)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if data, ok := strings.CutPrefix(line, "data: "); ok && strings.Contains(data, `"id":11`) {
				return res.StatusCode, []byte(data)
			}
		}
		t.Fatalf("no response event in stream: %s", raw)
	}
	return res.StatusCode, raw
}

func (f *fakeRemoteMCPServer) receivedCalls() []receivedToolsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]receivedToolsCall(nil), f.received...)
}

func (f *fakeRemoteMCPServer) calledTools() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func assertUnknownTool(t *testing.T, status int, body []byte, name string) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, status, string(body))
	var response struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &response), string(body))
	assert.Equal(t, mcp.JSONRPCInvalidParams, response.Error.Code)
	assert.Equal(t, `unknown tool "`+name+`"`, response.Error.Message)
	assert.JSONEq(t, `11`, string(response.ID))
}

func TestRemoteMCPToolView_CallToAnExposedNameReachesTheUpstreamTool(t *testing.T) {
	const params = `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"},"_meta":{"progressToken":"p-1"}}`
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }

	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				header     map[string]string
				wantHeader []string
			}{
				{name: "without Mcp-Name"},
				{name: "plain Mcp-Name", header: map[string]string{mcp.HeaderName: "open_issue"}, wantHeader: []string{"create_issue"}},
				{name: "base64 Mcp-Name", header: map[string]string{mcp.HeaderName: b64("open_issue")}, wantHeader: []string{b64("create_issue")}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-"+transport, transport == "sse",
						[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

					status, body := remoteMCPToolsCall(t, ts, "", params, tc.header)
					require.Equal(t, http.StatusOK, status, string(body))
					assert.JSONEq(t, `{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"called create_issue"}]}}`, string(body),
						"the upstream result is returned unchanged")

					calls := fake.receivedCalls()
					require.Len(t, calls, 1)
					assert.Equal(t, "create_issue", calls[0].Name, "the upstream receives its own tool name")
					assert.JSONEq(t, `{"repo":"tyk","title":"Crash on startup"}`, string(calls[0].Arguments))
					assert.JSONEq(t, `{"progressToken":"p-1"}`, string(calls[0].Meta))
					assert.JSONEq(t, `11`, string(calls[0].ID))
					assert.Equal(t, tc.wantHeader, calls[0].MCPName, "Mcp-Name matches the translated body")
				})
			}
		})
	}

	t.Run("modern request with mirrored headers", func(t *testing.T) {
		ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-modern", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)
		modernParams := `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"},"_meta":{"` + mcp.MetaKeyProtocolVersion + `":"` + mcp.ModernProtocolVersion + `","` + mcp.MetaKeyClientCapabilities + `":{},"` + mcp.MetaKeyClientInfo + `":{"name":"test","version":"1"}}}`

		status, body := remoteMCPToolsCall(t, ts, "", modernParams, map[string]string{
			mcp.HeaderProtocolVersion: mcp.ModernProtocolVersion,
			mcp.HeaderMethod:          "tools/call",
			mcp.HeaderName:            b64("open_issue"),
		})
		require.Equal(t, http.StatusOK, status, string(body))
		calls := fake.receivedCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, "create_issue", calls[0].Name)
		assert.Equal(t, []string{b64("create_issue")}, calls[0].MCPName)
	})

	t.Run("analytics keep the exposed name", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		fake, upstream := newFakeRemoteMCPServer(t, upstreamGitHubCreateIssue)
		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-call-analytics", upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()},
			func(spec *APISpec) { spec.DoNotTrack = false })
		waitForRemoteMCPToolViewCheck(t, spec)
		captured := captureAnalytics(ts)

		status, body := remoteMCPToolsCall(t, ts, "", params, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		require.Len(t, fake.receivedCalls(), 1)
		require.Eventually(t, func() bool { return captured.Load() != nil }, 5*time.Second, 10*time.Millisecond)
		assert.Equal(t, "open_issue", captured.Load().MCPStats.PrimitiveName)
	})
}

func TestRemoteMCPToolView_CallToARenamedAwayToolIsUnknown(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			t.Run("calling create_issue after it was renamed to open_issue is unknown", func(t *testing.T) {
				ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-unknown-"+transport, transport == "sse",
					[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)

				status, body := remoteMCPToolsCall(t, ts, "", `{"name":"create_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`, nil)
				assertUnknownTool(t, status, body, "create_issue")
				assert.Empty(t, fake.receivedCalls(), "the upstream receives nothing")
			})

			t.Run("swap dispatches each bound name and rejects the name renamed away", func(t *testing.T) {
				ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-unknown-swap-"+transport, transport == "sse", swapOverrides(),
					upstreamRemoveRepo, upstreamUpdateRepo)

				status, body := remoteMCPToolsCall(t, ts, "", `{"name":"update_repo","arguments":{}}`, nil)
				assertUnknownTool(t, status, body, "update_repo")

				status, body = remoteMCPToolsCall(t, ts, "", `{"name":"remove_repo","arguments":{}}`, nil)
				require.Equal(t, http.StatusOK, status, string(body))
				status, body = remoteMCPToolsCall(t, ts, "", `{"name":"delete_repo","arguments":{}}`, nil)
				require.Equal(t, http.StatusOK, status, string(body))

				assert.Equal(t, []string{"update_repo", "remove_repo"}, fake.calledTools())
			})
		})
	}

	t.Run("unauthenticated callers get the authentication error", func(t *testing.T) {
		ts, fake, spec := startRemoteMCPProxyWithView(t, "remote-mcp-unknown-unauthenticated", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)
		_ = createRemoteMCPKey(t, ts, spec, user.AccessControlRules{})

		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"create_issue","arguments":{}}`, nil)
		assert.Equal(t, http.StatusUnauthorized, status, string(body))
		assert.NotContains(t, string(body), "unknown tool")
		assert.Empty(t, fake.receivedCalls())
	})
}

func TestRemoteMCPToolView_CallsAuthorisedOnExposedNames(t *testing.T) {
	t.Run("a key blocking open_issue is denied the call", func(t *testing.T) {
		ts, fake, spec := startRemoteMCPProxyWithView(t, "remote-mcp-call-blocked", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
		key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"open_issue"}})

		status, body := remoteMCPToolsCall(t, ts, key, `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`, nil)
		assert.Equal(t, http.StatusForbidden, status, string(body))
		assert.Contains(t, string(body), "open_issue")

		status, body = remoteMCPToolsCall(t, ts, key, `{"name":"list_issues","arguments":{"repo":"tyk"}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, []string{"list_issues"}, fake.calledTools(), "the denied call never reaches the upstream")
	})

	t.Run("a key blocking the upstream name may call the renamed tool", func(t *testing.T) {
		ts, fake, spec := startRemoteMCPProxyWithView(t, "remote-mcp-call-renamed", false,
			[]oas.TykMCPServerPrimitive{renameOverride("delete_repo", "remove_repository")}, upstreamDeleteRepo)
		key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"delete_repo"}})

		status, body := remoteMCPToolsCall(t, ts, key, `{"name":"remove_repository","arguments":{"repo":"tyk"}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, []string{"delete_repo"}, fake.calledTools())
	})

	t.Run("after a swap, blocking remove_repo denies the tool exposed as remove_repo", func(t *testing.T) {
		ts, fake, spec := startRemoteMCPProxyWithView(t, "remote-mcp-call-swap-blocked", false, swapOverrides(),
			upstreamRemoveRepo, upstreamUpdateRepo)
		key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"remove_repo"}})

		status, body := remoteMCPToolsCall(t, ts, key, `{"name":"remove_repo","arguments":{}}`, nil)
		assert.Equal(t, http.StatusForbidden, status, string(body))
		status, body = remoteMCPToolsCall(t, ts, key, `{"name":"delete_repo","arguments":{}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, []string{"remove_repo"}, fake.calledTools())
	})

	t.Run("a rate limit on open_issue allows 5 calls a minute", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		fake, upstream := newFakeRemoteMCPServer(t, upstreamGitHubCreateIssue)
		primitives := []oas.TykMCPServerPrimitive{openIssueOverride()}
		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-call-rate-limit", upstream.URL, primitives, func(spec *APISpec) {
			spec.OAS = remoteMCPProxyOAS(upstream.URL, primitives, &oas.Middleware{McpTools: oas.MCPPrimitives{
				"open_issue": &oas.MCPPrimitive{Operation: oas.Operation{RateLimit: &oas.RateLimitEndpoint{
					Enabled: true, Rate: 5, Per: oas.ReadableDuration(time.Minute),
				}}},
			}})
			spec.OAS.ExtractTo(spec.APIDefinition)
			spec.APIID = "remote-mcp-call-rate-limit"
			spec.UseKeylessAccess = true
			spec.MarkAsMCP()
			spec.Proxy.ListenPath = remoteMCPListenPath
			spec.Proxy.TargetURL = upstream.URL
		})
		waitForRemoteMCPToolViewCheck(t, spec)
		require.NotNil(t, spec.MCPToolView())

		for i := range 5 {
			status, body := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`, nil)
			require.Equal(t, http.StatusOK, status, "call %d: %s", i+1, body)
		}
		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`, nil)
		assert.Equal(t, http.StatusTooManyRequests, status, string(body))
		assert.Equal(t, []string{"create_issue", "create_issue", "create_issue", "create_issue", "create_issue"}, fake.calledTools())
	})
}

func TestRemoteMCPToolView_CallAfterUpstreamDrift(t *testing.T) {
	t.Run("open_issue reaches create_issue, never the upstream's own open_issue", func(t *testing.T) {
		ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-drift-collision", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)
		fake.setTools(upstreamGitHubOpenIssue, upstreamGitHubCreateIssue)

		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, []string{"create_issue"}, fake.calledTools())
	})

	t.Run("a call whose source is missing upstream is forwarded under the source name", func(t *testing.T) {
		ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-drift-missing", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)
		fake.setTools(upstreamGitHubListIssues)

		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, []string{"create_issue"}, fake.calledTools(), "the upstream decides")
	})
}

func TestRemoteMCPToolView_McpNameHeaderFollowsTheDispatchedTool(t *testing.T) {
	for _, tc := range []struct {
		name         string
		params       string
		header       string
		wantUpstream string
	}{
		{
			name:         "a mismatched header on a call that is not translated carries the body's tool",
			params:       `{"name":"list_issues","arguments":{"repo":"tyk"}}`,
			header:       "create_issue",
			wantUpstream: "list_issues",
		},
		{
			name:         "a mismatched header on a translated call carries the upstream tool",
			params:       `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash on startup"}}`,
			header:       "list_issues",
			wantUpstream: "create_issue",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-header", false,
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

			status, body := remoteMCPToolsCall(t, ts, "", tc.params, map[string]string{mcp.HeaderName: tc.header})
			require.Equal(t, http.StatusOK, status, string(body))
			calls := fake.receivedCalls()
			require.Len(t, calls, 1)
			assert.Equal(t, tc.wantUpstream, calls[0].Name)
			assert.Equal(t, []string{tc.wantUpstream}, calls[0].MCPName)
		})
	}

	t.Run("a call without Mcp-Name is forwarded without one", func(t *testing.T) {
		ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-call-no-header", false,
			[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubListIssues)

		status, body := remoteMCPToolsCall(t, ts, "", `{"name":"list_issues","arguments":{"repo":"tyk"}}`, nil)
		require.Equal(t, http.StatusOK, status, string(body))
		calls := fake.receivedCalls()
		require.Len(t, calls, 1)
		assert.Empty(t, calls[0].MCPName)
	})
}

func TestRemoteMCPToolView_UnknownToolWithoutAnIDIsRejected(t *testing.T) {
	ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-unknown-no-id", false,
		[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue)

	req, err := http.NewRequest(http.MethodPost, ts.URL+remoteMCPListenPath,
		strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_issue","arguments":{}}}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, "2025-06-18")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, res.StatusCode, string(body))
	assert.Contains(t, string(body), `unknown tool \"create_issue\"`)
	assert.Empty(t, fake.receivedCalls(), "the upstream receives nothing")
}
