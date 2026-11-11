package catalogue

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMCPUpstream struct {
	mu       sync.Mutex
	pages    [][]string
	sse      bool
	session  string
	requests []string
	headers  []http.Header
}

func (f *fakeMCPUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.headers = append(f.headers, r.Header.Clone())
	if r.Method == http.MethodDelete {
		f.requests = append(f.requests, "DELETE")
		return
	}

	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Cursor string `json:"cursor"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, req.Method+":"+req.Params.Cursor)

	if req.Method != "initialize" && f.session != "" && r.Header.Get("Mcp-Session-Id") != f.session {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}

	var result any
	switch req.Method {
	case "initialize":
		if f.session != "" {
			w.Header().Set("Mcp-Session-Id", f.session)
		}
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fake", "version": "1"}}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		page := 0
		if req.Params.Cursor != "" {
			_, _ = fmt.Sscanf(req.Params.Cursor, "page-%d", &page)
		}
		tools := make([]map[string]any, 0, len(f.pages[page]))
		for _, name := range f.pages[page] {
			tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
		}
		res := map[string]any{"tools": tools}
		if page+1 < len(f.pages) {
			res["nextCursor"] = fmt.Sprintf("page-%d", page+1)
		}
		result = res
	default:
		http.Error(w, "unexpected method", http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\nevent: message\ndata: %s\n\n", body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func TestFetchToolNames(t *testing.T) {
	t.Parallel()

	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			upstream := &fakeMCPUpstream{pages: [][]string{{"create_issue", "delete_repo"}, {"remove_repo"}}, sse: sse, session: "session-1"}
			server := httptest.NewServer(upstream)
			t.Cleanup(server.Close)

			header := http.Header{}
			header.Set("Authorization", "Basic dGVzdDp0ZXN0")
			names, err := FetchToolNames(context.Background(), server.Client(), server.URL+"/mcp", header)
			require.NoError(t, err)
			assert.Equal(t, []string{"create_issue", "delete_repo", "remove_repo"}, names)

			upstream.mu.Lock()
			defer upstream.mu.Unlock()
			assert.Equal(t, []string{"initialize:", "notifications/initialized:", "tools/list:", "tools/list:page-1", "DELETE"}, upstream.requests)
			for _, h := range upstream.headers {
				assert.Equal(t, "Basic dGVzdDp0ZXN0", h.Get("Authorization"))
			}
			assert.Equal(t, "2025-06-18", upstream.headers[2].Get("MCP-Protocol-Version"))
		})
	}

	t.Run("upstream error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		t.Cleanup(server.Close)

		_, err := FetchToolNames(context.Background(), server.Client(), server.URL, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("repeated cursor stops pagination", func(t *testing.T) {
		upstream := &fakeMCPUpstream{pages: [][]string{{"a"}, {"b"}}}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && strings.Contains(r.Header.Get("MCP-Protocol-Version"), "2025") {
				var req struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.Method == "tools/list" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"a"}],"nextCursor":"same"}}`, req.ID)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				return
			}
			upstream.ServeHTTP(w, r)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := FetchToolNames(ctx, server.Client(), server.URL, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repeated")
	})
}

func TestFetchToolNames_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var redirectedHits int
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		redirectedHits++
		mu.Unlock()
	}))
	t.Cleanup(target.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)

	header := http.Header{}
	header.Set("X-Upstream-Auth", "Basic c2VjcmV0OnNlY3JldA==")
	_, err := FetchToolNames(context.Background(), &http.Client{}, origin.URL, header)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "307")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, redirectedHits, "the redirect target must never be contacted")
}
