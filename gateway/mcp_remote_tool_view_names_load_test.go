package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// blockingCatalogueUpstream serves fake but holds every initialize request,
// which only the catalogue check sends, until the test ends. Client requests
// go straight to tools/list and tools/call and are served at once.
func blockingCatalogueUpstream(t *testing.T, fake *fakeRemoteMCPServer) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.Contains(string(body), `"method":"initialize"`) {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		fake.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	// Cleanups run last-in first-out: release the check before closing.
	t.Cleanup(func() { close(release) })
	return upstream
}

// assertOpenIssueIsTheOverride checks that tools/list exposes exactly one
// open_issue, the renamed create_issue, and that calling it reaches
// create_issue.
func assertOpenIssueIsTheOverride(t *testing.T, ts *Test, fake *fakeRemoteMCPServer) {
	t.Helper()
	_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
	tools, names, _ := listedTools(t, body)
	assert.Equal(t, []string{"open_issue", "list_issues"}, names, "exactly one open_issue")
	assert.JSONEq(t, `"`+openIssueDescription+`"`, string(toolField(t, tools["open_issue"], "description")),
		"the listed open_issue is the overridden create_issue")
	assert.NotContains(t, string(body), "The upstream's own open_issue")

	status, call := remoteMCPToolsCall(t, ts, "", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash"}}`, nil)
	require.Equal(t, http.StatusOK, status, string(call))
	assert.Equal(t, []string{"create_issue"}, fake.calledTools(), "open_issue reaches create_issue, never the upstream's own open_issue")
}

func TestRemoteMCPToolView_CollisionAtLoad(t *testing.T) {
	t.Run("a fresh load exposes the override and hides the colliding upstream tool before the check finishes", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		fake, _ := newFakeRemoteMCPServer(t, upstreamGitHubOpenIssue, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
		upstream := blockingCatalogueUpstream(t, fake)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-load-collision-pending", upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()})
		assertOpenIssueIsTheOverride(t, ts, fake)
		select {
		case <-spec.remoteMCPToolViewCheckDone():
			t.Fatal("catalogue check finished while the upstream was still blocked")
		default:
		}
	})

	t.Run("a fresh load keeps the override after the check and warns about the collision", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-load-collision"
		logs := recordRemoteMCPLogs(t, apiID)
		fake, upstream := newFakeRemoteMCPServer(t, upstreamGitHubOpenIssue, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()})
		waitForRemoteMCPToolViewCheck(t, spec)

		assertOpenIssueIsTheOverride(t, ts, fake)
		assert.NotNil(t, logs.find(logrus.WarnLevel, "override wins", "exposed_name=open_issue", "source_tool=create_issue"))
	})

	t.Run("a reload that introduces the collision behaves like a fresh load", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-reload-collision-names"
		logs := recordRemoteMCPLogs(t, apiID)
		fake, upstream := newFakeRemoteMCPServer(t, upstreamGitHubOpenIssue, upstreamGitHubCreateIssue, upstreamGitHubListIssues)

		first := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("list_issues", oas.DerivedToolAnnotations{OpenWorldHint: boolPtr(false)}),
		})
		waitForRemoteMCPToolViewCheck(t, first)

		second := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{openIssueOverride()})
		waitForRemoteMCPToolViewCheck(t, second)

		assertOpenIssueIsTheOverride(t, ts, fake)
		assert.NotNil(t, logs.find(logrus.WarnLevel, "override wins", "exposed_name=open_issue"))
	})
}

func TestRemoteMCPToolView_RenamesThroughACompressedUpstream(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-gzip-renames-"+transport, transport == "sse",
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
			fake.mu.Lock()
			fake.encoding = "gzip"
			fake.mu.Unlock()

			list := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, list.status, string(list.raw))
			_, names, _ := listedTools(t, list.body)
			assert.Equal(t, []string{"open_issue", "list_issues"}, names, "the client sees the exposed name")

			call := remoteMCPCompressedRequest(t, ts, "", "tools/call", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash"}}`)
			require.Equal(t, http.StatusOK, call.status, string(call.raw))
			assert.Contains(t, string(call.body), "called create_issue")
			assert.Equal(t, []string{"create_issue"}, fake.calledTools())

			stale := remoteMCPCompressedRequest(t, ts, "", "tools/call", `{"name":"create_issue","arguments":{}}`)
			assertUnknownTool(t, stale.status, stale.body, "create_issue")
		})
	}
}

func TestRemoteMCPToolView_RenamesForABrPreferringClient(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-br-renames-"+transport, transport == "sse",
				[]oas.TykMCPServerPrimitive{openIssueOverride()}, upstreamGitHubCreateIssue, upstreamGitHubListIssues)
			fake.mu.Lock()
			fake.encoding = "negotiate"
			fake.mu.Unlock()

			// The client offers "br, gzip, deflate" and the upstream answers
			// with the first coding it is offered.
			list := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, list.status, string(list.raw))
			assert.NotEqual(t, "br", list.encoding)
			_, names, _ := listedTools(t, list.body)
			assert.Equal(t, []string{"open_issue", "list_issues"}, names, "the client sees the exposed name")

			call := remoteMCPCompressedRequest(t, ts, "", "tools/call", `{"name":"open_issue","arguments":{"repo":"tyk","title":"Crash"}}`)
			require.Equal(t, http.StatusOK, call.status, string(call.raw))
			assert.Equal(t, []string{"create_issue"}, fake.calledTools())
		})
	}
}
