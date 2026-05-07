package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeriveUpstreamPRMURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		err  bool
	}{
		{"path-bearing trailing slash stripped",
			"https://mcp.atlassian.com/v1/mcp/authv2/",
			"https://mcp.atlassian.com/.well-known/oauth-protected-resource/v1/mcp/authv2", false},
		{"path-bearing no trailing slash",
			"https://mcp.atlassian.com/v1/mcp/authv2",
			"https://mcp.atlassian.com/.well-known/oauth-protected-resource/v1/mcp/authv2", false},
		{"host root only",
			"https://upstream.example/",
			"https://upstream.example/.well-known/oauth-protected-resource", false},
		{"host root no slash",
			"https://upstream.example",
			"https://upstream.example/.well-known/oauth-protected-resource", false},
		{"empty rejected", "", "", true},
		{"non-URL rejected", "not a url", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveUpstreamPRMURL(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPRMCacheTTL(t *testing.T) {
	c := NewPRMCache(time.Hour)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return clock }

	doc := &PRMDocument{Raw: map[string]any{"resource": "https://x"}}
	c.Put("k", doc)

	if got, ok := c.Get("k"); !ok || got.Resource() != "https://x" {
		t.Fatalf("expected hit, got ok=%v doc=%v", ok, got)
	}

	clock = clock.Add(2 * time.Hour)
	if _, ok := c.Get("k"); ok {
		t.Fatalf("expected miss after TTL")
	}
}

func TestPRMCacheCloneIsolation(t *testing.T) {
	c := NewPRMCache(time.Minute)
	c.Put("k", &PRMDocument{Raw: map[string]any{"resource": "a"}})

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected hit")
	}
	got.Raw["resource"] = "mutated" // should not poison the cache

	got2, _ := c.Get("k")
	if got2.Resource() != "a" {
		t.Fatalf("cache poisoned: %q", got2.Resource())
	}
}

func TestFetchUpstreamPRM(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("MCP-Protocol-Version") == "" {
			t.Errorf("missing MCP-Protocol-Version header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://upstream.example/v1/mcp","authorization_servers":["https://auth.example/t"]}`))
	}))
	t.Cleanup(stub.Close)

	doc, err := FetchUpstreamPRM(context.Background(), stub.Client(), stub.URL+"/.well-known/oauth-protected-resource/v1/mcp")
	if err != nil {
		t.Fatalf("FetchUpstreamPRM: %v", err)
	}
	if doc.Resource() != "https://upstream.example/v1/mcp" {
		t.Fatalf("resource: %q", doc.Resource())
	}
	authServers, _ := doc.Raw["authorization_servers"].([]any)
	if len(authServers) != 1 || authServers[0] != "https://auth.example/t" {
		t.Fatalf("authorization_servers preserved: %v", authServers)
	}
}

func TestFetchUpstreamPRM_404(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	t.Cleanup(stub.Close)

	_, err := FetchUpstreamPRM(context.Background(), stub.Client(), stub.URL+"/x")
	if err == nil {
		t.Fatal("expected error on 404")
	}
}

func TestFetchUpstreamPRM_EmptyURL(t *testing.T) {
	_, err := FetchUpstreamPRM(context.Background(), http.DefaultClient, "")
	if err == nil {
		t.Fatal("expected error on empty URL")
	}
}

func TestFetchUpstreamPRM_MalformedJSON(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	t.Cleanup(stub.Close)

	_, err := FetchUpstreamPRM(context.Background(), stub.Client(), stub.URL+"/x")
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestPRMCacheInvalidate(t *testing.T) {
	c := NewPRMCache(time.Hour)
	c.Put("k", &PRMDocument{Raw: map[string]any{"resource": "https://x"}})
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected hit before invalidate")
	}
	c.Invalidate("k")
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss after invalidate")
	}
}

func TestPRMDocument_NilSafety(t *testing.T) {
	var d *PRMDocument
	if got := d.Resource(); got != "" {
		t.Fatalf("nil doc Resource() should be empty, got %q", got)
	}
	d.SetResource("https://x") // must not panic
	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "null" {
		t.Fatalf("nil doc MarshalJSON should be null, got %s", string(b))
	}
}

func TestPRMDocument_SetResourceInitsRaw(t *testing.T) {
	d := &PRMDocument{}
	d.SetResource("https://x")
	if d.Resource() != "https://x" {
		t.Fatalf("got %q", d.Resource())
	}
}

func TestNewPRMCache_DefaultTTLOnZero(t *testing.T) {
	c := NewPRMCache(0)
	if c.ttl != DefaultPRMCacheTTL {
		t.Fatalf("expected default TTL, got %v", c.ttl)
	}
}
