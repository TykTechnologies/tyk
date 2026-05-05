package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultPRMCacheTTL is how long a fetched upstream PRM document is reused
// before being refetched. Five minutes balances freshness against load
// against upstream OAuth metadata endpoints (which change rarely).
const DefaultPRMCacheTTL = 5 * time.Minute

// PRMDocument is a minimally-typed representation of an RFC 9728 Protected
// Resource Metadata document. We keep the parsed map alongside so unknown
// fields round-trip when we re-serialise after rewriting `resource`.
type PRMDocument struct {
	// Raw is the parsed JSON object. We rewrite Raw["resource"] in place
	// before serving so any provider-specific fields (e.g.
	// `bearer_methods_supported`, `resource_documentation`) are preserved.
	Raw map[string]any
}

// Resource returns the resource URL declared in the document, if any.
func (d *PRMDocument) Resource() string {
	if d == nil || d.Raw == nil {
		return ""
	}
	v, _ := d.Raw["resource"].(string)
	return v
}

// SetResource overwrites the document's resource field. Used to swap the
// upstream's URL for the gateway URL the client connected to before
// serving.
func (d *PRMDocument) SetResource(url string) {
	if d == nil {
		return
	}
	if d.Raw == nil {
		d.Raw = make(map[string]any)
	}
	d.Raw["resource"] = url
}

// MarshalJSON returns the document's JSON encoding.
func (d *PRMDocument) MarshalJSON() ([]byte, error) {
	if d == nil {
		return []byte("null"), nil
	}
	return json.Marshal(d.Raw)
}

// PRMCache holds upstream PRM documents indexed by upstream URL with TTL
// expiry. Safe for concurrent use.
type PRMCache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]prmCacheEntry
	now     func() time.Time // override for tests
}

type prmCacheEntry struct {
	doc       *PRMDocument
	expiresAt time.Time
}

// NewPRMCache constructs a cache with the given TTL. Pass 0 to use the
// package default.
func NewPRMCache(ttl time.Duration) *PRMCache {
	if ttl <= 0 {
		ttl = DefaultPRMCacheTTL
	}
	return &PRMCache{
		ttl:     ttl,
		entries: make(map[string]prmCacheEntry),
		now:     time.Now,
	}
}

// Get returns a cached document if present and unexpired. The bool is true
// when the returned document is valid.
func (c *PRMCache) Get(key string) (*PRMDocument, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.now().After(e.expiresAt) {
		return nil, false
	}
	return cloneDoc(e.doc), true
}

// Put stores a document in the cache with the cache-wide TTL.
func (c *PRMCache) Put(key string, doc *PRMDocument) {
	c.mu.Lock()
	c.entries[key] = prmCacheEntry{
		doc:       cloneDoc(doc),
		expiresAt: c.now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Invalidate removes the entry for a given key. Tests use this; runtime
// code can rely on TTL expiry.
func (c *PRMCache) Invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// cloneDoc returns a defensive copy so callers mutating Raw don't poison
// other consumers of the same cache entry.
func cloneDoc(d *PRMDocument) *PRMDocument {
	if d == nil {
		return nil
	}
	out := &PRMDocument{Raw: make(map[string]any, len(d.Raw))}
	for k, v := range d.Raw {
		out.Raw[k] = v
	}
	return out
}

// FetchUpstreamPRM retrieves the upstream's PRM document from the given URL
// using the supplied HTTP client. Caller is responsible for plugging in
// timeouts/transport via the client.
func FetchUpstreamPRM(ctx context.Context, client *http.Client, prmURL string) (*PRMDocument, error) {
	if prmURL == "" {
		return nil, errors.New("upstream PRM URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prmURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build PRM request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2024-11-05")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch upstream PRM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("upstream PRM returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode upstream PRM: %w", err)
	}
	return &PRMDocument{Raw: raw}, nil
}

// DeriveUpstreamPRMURL builds the path-suffix variant URL where a remote
// resource server publishes its PRM doc per RFC 9728 §3.1:
//
//	<scheme>://<host>/.well-known/oauth-protected-resource<resource-path>
//
// Trailing slashes on the resource path are stripped to match the form
// most clients (notably mcp-remote) actually probe.
func DeriveUpstreamPRMURL(upstreamURL string) (string, error) {
	if upstreamURL == "" {
		return "", errors.New("upstream URL is empty")
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return "", fmt.Errorf("parse upstream URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("upstream URL %q has no scheme/host", upstreamURL)
	}
	path := strings.TrimRight(u.Path, "/")
	prm := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   "/.well-known/oauth-protected-resource" + path,
	}
	return prm.String(), nil
}
