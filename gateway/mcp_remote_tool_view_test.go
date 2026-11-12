package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// fakeRemoteMCPServer is a minimal Streamable HTTP MCP server for remote
// proxy tests. Tools are raw JSON objects so tests control every field.
type fakeRemoteMCPServer struct {
	t         *testing.T
	mu        sync.Mutex
	tools     []json.RawMessage
	pageSize  int
	sse       bool
	listCalls int
	calls     []string
	received  []receivedToolsCall
	block     chan struct{}
}

// receivedToolsCall is what the upstream saw for one tools/call.
type receivedToolsCall struct {
	ID        json.RawMessage
	Name      string
	Arguments json.RawMessage
	Meta      json.RawMessage
	MCPName   []string
}

func (f *fakeRemoteMCPServer) setTools(tools ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools = f.tools[:0]
	for _, tool := range tools {
		f.tools = append(f.tools, json.RawMessage(tool))
	}
}

func (f *fakeRemoteMCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-r.Context().Done():
			return
		}
	}
	if r.Method != http.MethodPost {
		return
	}

	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Cursor    string          `json:"cursor"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	var result string
	switch req.Method {
	case "initialize":
		result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}`
	case "notifications/initialized":
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		f.listCalls++
		page, err := f.toolsListPage(req.Params.Cursor)
		if err != nil {
			f.mu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result = page
	case "tools/call":
		f.calls = append(f.calls, req.Params.Name)
		f.received = append(f.received, receivedToolsCall{
			ID: req.ID, Name: req.Params.Name, Arguments: req.Params.Arguments, Meta: req.Params.Meta,
			MCPName: r.Header.Values("Mcp-Name"),
		})
		result = `{"content":[{"type":"text","text":"called ` + req.Params.Name + `"}]}`
	default:
		f.mu.Unlock()
		http.Error(w, "unexpected method", http.StatusBadRequest)
		return
	}
	sse := f.sse
	f.mu.Unlock()

	body := `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", body); err != nil {
			f.t.Errorf("writing %s event: %v", req.Method, err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(body)); err != nil {
		f.t.Errorf("writing %s response: %v", req.Method, err)
	}
}

// toolsListPage returns the tools/list result for cursor. The caller holds
// f.mu.
func (f *fakeRemoteMCPServer) toolsListPage(cursor string) (string, error) {
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "offset-%d", &start); err != nil || start < 0 || start > len(f.tools) {
			return "", fmt.Errorf("invalid cursor %q", cursor)
		}
	}
	end := len(f.tools)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	parts := make([]string, 0, end-start)
	for _, tool := range f.tools[start:end] {
		parts = append(parts, string(tool))
	}
	result := `{"tools":[` + strings.Join(parts, ",") + `]`
	if end < len(f.tools) {
		result += fmt.Sprintf(`,"nextCursor":"offset-%d"`, end)
	}
	return result + `,"_meta":{"upstream":"kept"}}`, nil
}

func newFakeRemoteMCPServer(t *testing.T, tools ...string) (*fakeRemoteMCPServer, *httptest.Server) {
	t.Helper()
	fake := &fakeRemoteMCPServer{t: t}
	fake.setTools(tools...)
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, server
}

const remoteMCPListenPath = "/github-mcp/"

func remoteMCPProxyOAS(upstreamURL string, primitives []oas.TykMCPServerPrimitive, middleware *oas.Middleware) oas.OAS {
	doc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "GitHub MCP", Version: "1.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info:       oas.Info{Name: "github-mcp", State: oas.State{Active: true}},
		Upstream:   oas.Upstream{URL: upstreamURL},
		Server:     oas.Server{ListenPath: oas.ListenPath{Value: remoteMCPListenPath, Strip: true}},
		Middleware: middleware,
	})
	if len(primitives) > 0 {
		doc.SetTykMCPServerExtension(&oas.TykMCPServer{Primitives: primitives})
	}
	return doc
}

func loadRemoteMCPProxy(t *testing.T, ts *Test, apiID, upstreamURL string, primitives []oas.TykMCPServerPrimitive, configure ...func(*APISpec)) *APISpec {
	t.Helper()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = remoteMCPListenPath
		spec.Proxy.TargetURL = upstreamURL
		spec.IsOAS = true
		spec.OAS = remoteMCPProxyOAS(upstreamURL, primitives, nil)
		for _, fn := range configure {
			fn(spec)
		}
	})
	spec := ts.Gw.getApiSpec(apiID)
	require.NotNil(t, spec)
	return spec
}

func waitForRemoteMCPToolViewCheck(t *testing.T, spec *APISpec) {
	t.Helper()
	require.NotNil(t, spec.remoteMCPToolViewCheckDone(), "no catalogue check was started")
	select {
	case <-spec.remoteMCPToolViewCheckDone():
	case <-time.After(5 * time.Second):
		t.Fatal("catalogue check did not finish")
	}
}

type remoteMCPLogEntry struct {
	level logrus.Level
	text  string
}

type remoteMCPLogRecorder struct {
	mu      sync.Mutex
	entries []remoteMCPLogEntry
}

func (r *remoteMCPLogRecorder) record(entry *logrus.Entry) {
	text := entry.Message
	for key, value := range entry.Data {
		text += fmt.Sprintf(" %s=%v", key, value)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, remoteMCPLogEntry{level: entry.Level, text: text})
}

// remoteMCPLogDispatcher is added to the global logger once and never
// removed, so tests never change the logger's hooks or level while gateway
// goroutines log. It routes entries to recorders registered by API ID.
type remoteMCPLogDispatcher struct {
	mu        sync.Mutex
	recorders map[string]*remoteMCPLogRecorder
}

func (d *remoteMCPLogDispatcher) Levels() []logrus.Level {
	return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel}
}

func (d *remoteMCPLogDispatcher) Fire(entry *logrus.Entry) error {
	apiID, _ := entry.Data["api_id"].(string)
	d.mu.Lock()
	recorder := d.recorders[apiID]
	d.mu.Unlock()
	if recorder != nil {
		recorder.record(entry)
	}
	return nil
}

var (
	remoteMCPLogs     = &remoteMCPLogDispatcher{recorders: map[string]*remoteMCPLogRecorder{}}
	remoteMCPLogsOnce sync.Once
)

func (r *remoteMCPLogRecorder) find(level logrus.Level, contains ...string) *remoteMCPLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, entry := range r.entries {
		if entry.level != level {
			continue
		}
		matched := true
		for _, want := range contains {
			if !strings.Contains(entry.text, want) {
				matched = false
				break
			}
		}
		if matched {
			return &r.entries[i]
		}
	}
	return nil
}

func (r *remoteMCPLogRecorder) count(level logrus.Level, contains string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, entry := range r.entries {
		if entry.level == level && strings.Contains(entry.text, contains) {
			n++
		}
	}
	return n
}

// recordRemoteMCPLogs captures warnings and errors logged for one API ID.
func recordRemoteMCPLogs(t *testing.T, apiID string) *remoteMCPLogRecorder {
	t.Helper()
	remoteMCPLogsOnce.Do(func() { log.AddHook(remoteMCPLogs) })
	// The level is an atomic value, so raising it does not race with
	// goroutines that are logging.
	if log.GetLevel() < logrus.WarnLevel {
		log.SetTestLogLevel(t, logrus.WarnLevel)
	}
	recorder := &remoteMCPLogRecorder{}
	remoteMCPLogs.mu.Lock()
	remoteMCPLogs.recorders[apiID] = recorder
	remoteMCPLogs.mu.Unlock()
	t.Cleanup(func() {
		remoteMCPLogs.mu.Lock()
		delete(remoteMCPLogs.recorders, apiID)
		remoteMCPLogs.mu.Unlock()
	})
	return recorder
}

func renameOverride(source, name string) oas.TykMCPServerPrimitive {
	return oas.TykMCPServerPrimitive{Source: oas.TykMCPServerSource{ToolName: source}, Name: name}
}

func annotationOverride(source string, annotations oas.DerivedToolAnnotations) oas.TykMCPServerPrimitive {
	return oas.TykMCPServerPrimitive{Source: oas.TykMCPServerSource{ToolName: source}, Annotations: &annotations}
}

func TestRemoteMCPToolView_CatalogueCheckOnLoad(t *testing.T) {
	t.Run("admits the view after a clean catalogue check and warns about missing sources", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-clean"
		logs := recordRemoteMCPLogs(t, apiID)
		fake, upstream := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`, `{"name":"create_issue"}`)
		fake.pageSize = 1

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
			annotationOverride("archived_tool", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true)}),
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.NotNil(t, spec.MCPToolView())
		assert.Equal(t, 2, fake.listCalls, "the check must read every tools/list page")
		assert.NotNil(t, logs.find(logrus.WarnLevel, "archived_tool"), "missing source tool must be logged as a warning")
	})

	t.Run("brand-new API with a catalogue collision serves without overrides", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-collision"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, `{"name":"remove_repo"}`, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{renameOverride("remove_repo", "delete_repo")})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.Nil(t, spec.MCPToolView())
		assert.NotNil(t, logs.find(logrus.ErrorLevel, `"delete_repo" would be exposed by two tools`))
	})

	t.Run("reload with a catalogue collision keeps the previously admitted view", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-reload-collision"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, `{"name":"remove_repo"}`, `{"name":"delete_repo"}`)

		first := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		})
		waitForRemoteMCPToolViewCheck(t, first)
		admitted := first.MCPToolView()
		require.NotNil(t, admitted)

		second := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{renameOverride("remove_repo", "delete_repo")})
		require.NotSame(t, first, second)
		waitForRemoteMCPToolViewCheck(t, second)

		assert.Same(t, admitted, second.MCPToolView())
		assert.NotNil(t, logs.find(logrus.ErrorLevel, `"delete_repo" would be exposed by two tools`))
	})

	t.Run("unreachable upstream keeps the compiled view and logs a warning", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-unreachable"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t)
		upstreamURL := upstream.URL
		upstream.Close()

		spec := loadRemoteMCPProxy(t, ts, apiID, upstreamURL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assert.NotNil(t, spec.MCPToolView())
		assert.NotNil(t, logs.find(logrus.WarnLevel, "catalogue"))
	})

	t.Run("a slow upstream does not block loading", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		fake, upstream := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		fake.block = make(chan struct{})
		t.Cleanup(func() { close(fake.block) })

		started := time.Now()
		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-slow", upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		})
		assert.Less(t, time.Since(started), remoteMCPCatalogueTimeout)
		assert.Nil(t, spec.MCPToolView(), "the view is admitted only after the check")
		require.NotNil(t, spec.remoteMCPToolViewCheckDone())
		select {
		case <-spec.remoteMCPToolViewCheckDone():
			t.Fatal("catalogue check finished while the upstream was still blocked")
		default:
		}
	})

	t.Run("upstream basic auth is sent to the catalogue check", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		var gotAuth string
		var mu sync.Mutex
		fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotAuth = r.Header.Get("Authorization")
			mu.Unlock()
			fake.ServeHTTP(w, r)
		}))
		t.Cleanup(upstream.Close)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-basic-auth", upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		}, func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled:   true,
				BasicAuth: apidef.UpstreamBasicAuth{Enabled: true, Username: "catalogue", Password: "check"},
			}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "Basic Y2F0YWxvZ3VlOmNoZWNr", gotAuth)
	})

	t.Run("a redirecting upstream is not followed and the credential stays put", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-redirect"
		logs := recordRemoteMCPLogs(t, apiID)

		var redirectedHits int
		var mu sync.Mutex
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			mu.Lock()
			redirectedHits++
			mu.Unlock()
		}))
		t.Cleanup(target.Close)
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/mcp", http.StatusFound)
		}))
		t.Cleanup(origin.Close)

		spec := loadRemoteMCPProxy(t, ts, apiID, origin.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		}, func(spec *APISpec) {
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled: true, Username: "catalogue", Password: "check",
					Header: apidef.AuthSource{Enabled: true, Name: "X-Upstream-Auth"},
				},
			}
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		mu.Lock()
		assert.Zero(t, redirectedHits, "the redirect target must never be contacted")
		mu.Unlock()
		assert.NotNil(t, spec.MCPToolView(), "a redirect is handled like an unreachable upstream")
		assert.NotNil(t, logs.find(logrus.WarnLevel, "302"))
	})

	t.Run("proxies without overrides start no check", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		_, upstream := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, "remote-mcp-plain", upstream.URL, nil)
		assert.Nil(t, spec.remoteMCPToolViewCheckDone())
		assert.Nil(t, spec.MCPToolView())
	})
}

const (
	upstreamDeleteRepo  = `{"name":"delete_repo","description":"Delete a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}}}}`
	upstreamCreateIssue = `{"name":"create_issue","title":"Create issue","description":"Open an issue","inputSchema":{"type":"object"},"annotations":{"idempotentHint":false,"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`
	upstreamMergeBranch = `{"name":"merge_branch","inputSchema":{"type":"object"},"annotations":{"idempotentHint":true,"openWorldHint":true}}`
	upstreamListRepos   = `{"name":"list_repos","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true},"outputSchema":{"type":"object"}}`
)

func githubToolOverrides() []oas.TykMCPServerPrimitive {
	return []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		annotationOverride("create_issue", oas.DerivedToolAnnotations{Title: "Create GitHub issue"}),
		annotationOverride("merge_branch", oas.DerivedToolAnnotations{IdempotentHint: boolPtr(false), OpenWorldHint: boolPtr(false)}),
	}
}

// remoteMCPRequest sends one JSON-RPC request through the gateway and returns
// the JSON-RPC response, unwrapped from an SSE stream when needed.
func remoteMCPRequest(t *testing.T, ts *Test, key, method, params string) (int, http.Header, []byte) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":11,"method":"` + method + `","params":` + params + `}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+remoteMCPListenPath, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if key != "" {
		req.Header.Set("Authorization", key)
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if data, ok := strings.CutPrefix(line, "data: "); ok && strings.Contains(data, `"id":11`) {
				return res.StatusCode, res.Header, []byte(data)
			}
		}
		t.Fatalf("no response event in stream: %s", raw)
	}
	return res.StatusCode, res.Header, raw
}

func listedTools(t *testing.T, body []byte) (map[string]json.RawMessage, []string, map[string]json.RawMessage) {
	t.Helper()
	var envelope struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	var tools []json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.Result["tools"], &tools), string(body))
	byName := map[string]json.RawMessage{}
	var names []string
	for _, tool := range tools {
		var named struct {
			Name string `json:"name"`
		}
		require.NoError(t, json.Unmarshal(tool, &named))
		byName[named.Name] = tool
		names = append(names, named.Name)
	}
	return byName, names, envelope.Result
}

func startRemoteMCPProxyWithView(t *testing.T, apiID string, sse bool, primitives []oas.TykMCPServerPrimitive, tools ...string) (*Test, *fakeRemoteMCPServer, *APISpec) {
	t.Helper()
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	fake, upstream := newFakeRemoteMCPServer(t, tools...)
	spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, primitives)
	waitForRemoteMCPToolViewCheck(t, spec)
	require.NotNil(t, spec.MCPToolView())
	fake.mu.Lock()
	fake.sse = sse
	fake.mu.Unlock()
	return ts, fake, spec
}

func TestRemoteMCPToolView_ToolsListAnnotations(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, _, _ := startRemoteMCPProxyWithView(t, "remote-mcp-annotations-"+transport, transport == "sse", githubToolOverrides(),
				upstreamDeleteRepo, upstreamCreateIssue, upstreamMergeBranch, upstreamListRepos)

			status, header, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, status, string(body))
			assert.Equal(t, transport == "sse", strings.HasPrefix(header.Get("Content-Type"), "text/event-stream"))
			tools, names, result := listedTools(t, body)

			assert.Equal(t, []string{"delete_repo", "create_issue", "merge_branch", "list_repos"}, names)
			t.Run("delete_repo without upstream annotations marked destructive", func(t *testing.T) {
				assert.JSONEq(t, `{"name":"delete_repo","description":"Delete a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}}},"annotations":{"destructiveHint":true}}`, string(tools["delete_repo"]))
			})
			t.Run("idempotentHint and openWorldHint true overridden with false", func(t *testing.T) {
				assert.JSONEq(t, `{"name":"merge_branch","inputSchema":{"type":"object"},"annotations":{"idempotentHint":false,"openWorldHint":false}}`, string(tools["merge_branch"]))
			})
			t.Run("only annotations.title changes; upstream hints and top-level title kept", func(t *testing.T) {
				assert.JSONEq(t, `{"name":"create_issue","title":"Create issue","description":"Open an issue","inputSchema":{"type":"object"},"annotations":{"title":"Create GitHub issue","idempotentHint":false,"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`, string(tools["create_issue"]))
			})
			t.Run("tool without override unchanged and result fields kept", func(t *testing.T) {
				assert.JSONEq(t, upstreamListRepos, string(tools["list_repos"]))
				assert.JSONEq(t, `{"upstream":"kept"}`, string(result["_meta"]))
			})
		})
	}
}

func TestRemoteMCPToolView_ToolsListPagination(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-pages-"+transport, transport == "sse", githubToolOverrides(),
				upstreamListRepos, upstreamDeleteRepo)
			fake.mu.Lock()
			fake.pageSize = 1
			fake.mu.Unlock()

			_, _, first := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
			tools, _, result := listedTools(t, first)
			assert.JSONEq(t, upstreamListRepos, string(tools["list_repos"]))
			assert.JSONEq(t, `"offset-1"`, string(result["nextCursor"]))

			_, _, second := remoteMCPRequest(t, ts, "", "tools/list", `{"cursor":"offset-1"}`)
			tools, _, result = listedTools(t, second)
			assert.JSONEq(t, `{"destructiveHint":true}`, extractAnnotations(t, tools["delete_repo"]))
			assert.NotContains(t, result, "nextCursor")
		})
	}
}

func extractAnnotations(t *testing.T, tool json.RawMessage) string {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(tool, &fields))
	return string(fields["annotations"])
}

func TestRemoteMCPToolView_MissingSourceToolIsOmittedWithAWarning(t *testing.T) {
	const apiID = "remote-mcp-missing-source"
	ts, fake, _ := startRemoteMCPProxyWithView(t, apiID, false, []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		annotationOverride("archived_tool", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true)}),
	}, upstreamDeleteRepo, upstreamListRepos)
	logs := recordRemoteMCPLogs(t, apiID)

	for range 3 {
		_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
		_, names, _ := listedTools(t, body)
		assert.Equal(t, []string{"delete_repo", "list_repos"}, names)
	}

	assert.NotNil(t, logs.find(logrus.WarnLevel, "archived_tool"))
	assert.Equal(t, 1, logs.count(logrus.WarnLevel, "archived_tool"), "the warning is rate limited")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Equal(t, 4, fake.listCalls, "one catalogue check plus three client requests")
}

func TestRemoteMCPToolView_ToolsListCombinedWithAccessRules(t *testing.T) {
	ts, _, spec := startRemoteMCPProxyWithView(t, "remote-mcp-acl", false, githubToolOverrides(),
		upstreamDeleteRepo, upstreamCreateIssue, upstreamListRepos)
	key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"list_repos"}})

	status, _, body := remoteMCPRequest(t, ts, key, "tools/list", `{}`)
	require.Equal(t, http.StatusOK, status, string(body))
	tools, names, _ := listedTools(t, body)
	assert.Equal(t, []string{"delete_repo", "create_issue"}, names)
	assert.JSONEq(t, `{"destructiveHint":true}`, extractAnnotations(t, tools["delete_repo"]))
}

func createRemoteMCPKey(t *testing.T, ts *Test, spec *APISpec, tools user.AccessControlRules) string {
	t.Helper()
	ts.Gw.BuildAndLoadAPI(func(s *APISpec) {
		*s.APIDefinition = *spec.APIDefinition
		s.UseKeylessAccess = false
		s.IsOAS = true
		s.OAS = spec.OAS
	})
	reloaded := ts.Gw.getApiSpec(spec.APIID)
	waitForRemoteMCPToolViewCheck(t, reloaded)
	require.NotNil(t, reloaded.MCPToolView())

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{spec.APIID: {
			APIID:           spec.APIID,
			MCPAccessRights: user.MCPAccessRights{Tools: tools},
		}}
	})
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{policyID}
	})
	return key
}

func TestRemoteMCPToolView_AnnotationsDoNotChangeEnforcement(t *testing.T) {
	ts, fake, spec := startRemoteMCPProxyWithView(t, "remote-mcp-enforcement", false, []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true), DestructiveHint: boolPtr(false)}),
	}, upstreamDeleteRepo, upstreamListRepos)
	key := createRemoteMCPKey(t, ts, spec, user.AccessControlRules{Blocked: []string{"delete_repo"}})

	status, _, body := remoteMCPRequest(t, ts, key, "tools/call", `{"name":"delete_repo","arguments":{"repo":"tyk"}}`)
	assert.Equal(t, http.StatusForbidden, status, string(body))

	status, _, body = remoteMCPRequest(t, ts, key, "tools/call", `{"name":"list_repos","arguments":{}}`)
	assert.Equal(t, http.StatusOK, status, string(body))

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Equal(t, []string{"list_repos"}, fake.calls, "the blocked call must not reach the upstream")
}

func TestRemoteMCPToolView_CacheBypass(t *testing.T) {
	for _, method := range []string{"tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			_, _, spec := startRemoteMCPProxyWithView(t, "remote-mcp-cache-"+strings.ReplaceAll(method, "/", "-"), false,
				githubToolOverrides(), upstreamDeleteRepo)
			spec.CacheOptions.EnableCache = true

			req := httptest.NewRequest(http.MethodPost, remoteMCPListenPath, nil)
			httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: method})
			store := &cacheReadCountingStore{DummyStorage: storage.NewDummyStorage(), written: make(chan struct{}, 1)}
			require.NoError(t, store.DummyStorage.SetKey("cached-before-overrides", "stale", 60))
			ctxSetCacheOptions(req, &cacheOptions{key: "cached-before-overrides", timeout: 60})

			reader := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}, store: store}
			err, status := reader.ProcessRequest(httptest.NewRecorder(), req, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			assert.Zero(t, store.getCalls, "the cache must not be read")
			assert.Nil(t, ctxGetCacheOptions(req))

			ctxSetCacheOptions(req, &cacheOptions{key: "must-not-be-written", timeout: 60})
			writer := &ResponseCacheMiddleware{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec}, store: store}
			res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader("{}"))}
			require.NoError(t, writer.HandleResponse(httptest.NewRecorder(), res, req, nil))
			select {
			case <-store.written:
				t.Fatal("response was cached")
			default:
			}
		})
	}
}

func TestRemoteMCPToolView_NoViewLeavesToolsListUntouched(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	_, upstream := newFakeRemoteMCPServer(t, upstreamCreateIssue)
	spec := loadRemoteMCPProxy(t, ts, "remote-mcp-no-view", upstream.URL, nil)
	require.Nil(t, spec.MCPToolView())

	_, _, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":11,"result":{"tools":[`+upstreamCreateIssue+`],"_meta":{"upstream":"kept"}}}`, string(body))
}

func TestRemoteMCPToolView_ResponseCacheThroughTheGateway(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	const apiID = "remote-mcp-cached"
	_, upstream := newFakeRemoteMCPServer(t, upstreamDeleteRepo, upstreamListRepos)

	withCache := func(spec *APISpec) {
		spec.CacheOptions.EnableCache = true
		spec.CacheOptions.CacheTimeout = 60
		spec.VersionData.NotVersioned = true
		version := spec.VersionData.Versions["Default"]
		version.UseExtendedPaths = true
		version.ExtendedPaths.AdvanceCacheConfig = []apidef.CacheMeta{{Method: http.MethodPost, Path: "/"}}
		spec.VersionData.Versions["Default"] = version
	}
	cachedDeleteRepo := func() (string, string) {
		_, header, body := remoteMCPRequest(t, ts, "", "tools/list", `{}`)
		tools, _, _ := listedTools(t, body)
		return header.Get(cachedResponseHeader), extractAnnotations(t, tools["delete_repo"])
	}

	spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, nil, withCache)
	require.Nil(t, spec.MCPToolView())
	_, annotations := cachedDeleteRepo()
	assert.Empty(t, annotations)
	cached, _ := cachedDeleteRepo()
	require.Equal(t, "1", cached, "control: without a tool view the second tools/list is served from the cache")

	spec = loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
	}, withCache)
	waitForRemoteMCPToolViewCheck(t, spec)
	for range 2 {
		cached, annotations = cachedDeleteRepo()
		assert.Empty(t, cached, "the entry cached before the overrides must not be served")
		assert.JSONEq(t, `{"destructiveHint":true}`, annotations)
	}

	spec = loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(false), Title: "Delete repository"}),
	}, withCache)
	waitForRemoteMCPToolViewCheck(t, spec)
	cached, annotations = cachedDeleteRepo()
	assert.Empty(t, cached)
	assert.JSONEq(t, `{"destructiveHint":false,"title":"Delete repository"}`, annotations, "a changed override is applied, not a stale response")
}
