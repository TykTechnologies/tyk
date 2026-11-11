package gateway

import (
	"encoding/json"
	"fmt"
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
)

// fakeRemoteMCPServer is a minimal Streamable HTTP MCP server for remote
// proxy tests. Tools are raw JSON objects so tests control every field.
type fakeRemoteMCPServer struct {
	mu        sync.Mutex
	tools     []json.RawMessage
	pageSize  int
	sse       bool
	listCalls int
	calls     []string
	block     chan struct{}
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
			Name   string `json:"name"`
			Cursor string `json:"cursor"`
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
		start := 0
		if req.Params.Cursor != "" {
			_, _ = fmt.Sscanf(req.Params.Cursor, "offset-%d", &start)
		}
		end := len(f.tools)
		if f.pageSize > 0 && start+f.pageSize < end {
			end = start + f.pageSize
		}
		parts := make([]string, 0, end-start)
		for _, tool := range f.tools[start:end] {
			parts = append(parts, string(tool))
		}
		result = `{"tools":[` + strings.Join(parts, ",") + `]`
		if end < len(f.tools) {
			result += fmt.Sprintf(`,"nextCursor":"offset-%d"`, end)
		}
		result += `,"_meta":{"upstream":"kept"}}`
	case "tools/call":
		f.calls = append(f.calls, req.Params.Name)
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
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func newFakeRemoteMCPServer(t *testing.T, tools ...string) (*fakeRemoteMCPServer, *httptest.Server) {
	t.Helper()
	fake := &fakeRemoteMCPServer{}
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
