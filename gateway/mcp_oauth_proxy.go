package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/header"
)

// mcpASProxyPathPrefix is the base under which Tyk publishes per-API
// internal OAuth Authorization Server proxy endpoints when mirror mode is
// enabled. The shape is `<gateway-root>/__tyk-as/<api-id>/...`.
const mcpASProxyPathPrefix = "/__tyk-as/"

// mcpASProxyBaseURL builds the public URL Tyk advertises as the
// authorization server in a mirrored PRM doc. It is per-API so each MCP
// proxy gets its own scope under the gateway root.
func mcpASProxyBaseURL(r *http.Request, spec *APISpec) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s%s", scheme, r.Host, mcpASProxyPathPrefix, spec.APIID)
}

// upstreamResourceURL is the canonical URL the AS knows the resource by.
// Used as the value we substitute in for the `resource` parameter when
// proxying the authorize/token flow on behalf of the client.
func upstreamResourceURL(spec *APISpec) string {
	return spec.Proxy.TargetURL
}

// rewriteResourceParam swaps the `resource` parameter (RFC 8707) value to
// the upstream URL. Strict authorization servers — Notion as of 2026-Q2 —
// reject the gateway URL with `invalid_target`; the upstream URL is the
// only value they recognise.
func rewriteResourceParam(values url.Values, spec *APISpec) {
	if _, ok := values["resource"]; !ok {
		return
	}
	values.Set("resource", upstreamResourceURL(spec))
}

// serveASProxyMetadata fetches the upstream Authorization Server metadata
// document, rewrites `authorization_endpoint` and `token_endpoint` to
// point at Tyk's per-API proxy endpoints, and serves the result.
//
// `registration_endpoint` is left unchanged: Dynamic Client Registration
// (RFC 7591) does not carry a `resource` parameter so there's nothing to
// rewrite there, and avoiding the proxy keeps the DCR flow minimal.
func (gw *Gateway) serveASProxyMetadata(spec *APISpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asURL, err := gw.firstAuthorizationServer(r.Context(), spec)
		if err != nil {
			log.WithError(err).Warn("AS proxy: cannot resolve upstream authorization server")
			http.Error(w, "upstream authorization server unavailable", http.StatusBadGateway)
			return
		}

		metadata, err := fetchUpstreamASMetadata(r.Context(), asURL)
		if err != nil {
			log.WithError(err).Warn("AS proxy: cannot fetch upstream metadata")
			http.Error(w, "upstream AS metadata unavailable", http.StatusBadGateway)
			return
		}

		base := mcpASProxyBaseURL(r, spec)
		metadata["authorization_endpoint"] = base + "/authorize"
		metadata["token_endpoint"] = base + "/token"

		w.Header().Set(header.ContentType, "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	}
}

// authorizeProxyHandler 302-redirects the client's authorize request to
// the real upstream authorize endpoint after rewriting the `resource`
// parameter so the upstream AS recognises it.
func (gw *Gateway) authorizeProxyHandler(spec *APISpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asURL, err := gw.firstAuthorizationServer(r.Context(), spec)
		if err != nil {
			http.Error(w, "upstream authorization server unavailable", http.StatusBadGateway)
			return
		}
		metadata, err := fetchUpstreamASMetadata(r.Context(), asURL)
		if err != nil {
			http.Error(w, "upstream AS metadata unavailable", http.StatusBadGateway)
			return
		}
		realAuthorize, _ := metadata["authorization_endpoint"].(string)
		if realAuthorize == "" {
			http.Error(w, "upstream metadata missing authorization_endpoint", http.StatusBadGateway)
			return
		}

		target, err := url.Parse(realAuthorize)
		if err != nil {
			http.Error(w, "invalid upstream authorization_endpoint", http.StatusBadGateway)
			return
		}

		q := r.URL.Query()
		rewriteResourceParam(q, spec)
		// Merge any query already present on the upstream authorize URL.
		if upstreamQ := target.Query(); len(upstreamQ) > 0 {
			for k, vs := range upstreamQ {
				if _, ok := q[k]; !ok {
					q[k] = vs
				}
			}
		}
		target.RawQuery = q.Encode()

		http.Redirect(w, r, target.String(), http.StatusFound)
	}
}

// tokenProxyHandler forwards the client's token request to the upstream
// token endpoint, rewriting the `resource` form field on the way through.
// Returns the upstream response unmodified.
func (gw *Gateway) tokenProxyHandler(spec *APISpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asURL, err := gw.firstAuthorizationServer(r.Context(), spec)
		if err != nil {
			http.Error(w, "upstream authorization server unavailable", http.StatusBadGateway)
			return
		}
		metadata, err := fetchUpstreamASMetadata(r.Context(), asURL)
		if err != nil {
			http.Error(w, "upstream AS metadata unavailable", http.StatusBadGateway)
			return
		}
		realToken, _ := metadata["token_endpoint"].(string)
		if realToken == "" {
			http.Error(w, "upstream metadata missing token_endpoint", http.StatusBadGateway)
			return
		}

		// Re-parse the form so we can rewrite `resource` regardless of
		// whether it was sent as a query string or form body.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "cannot parse token request", http.StatusBadRequest)
			return
		}
		rewriteResourceParam(r.PostForm, spec)
		rewriteResourceParam(r.Form, spec)

		body := r.PostForm.Encode()

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, realToken, strings.NewReader(body))
		if err != nil {
			http.Error(w, "cannot build upstream token request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", r.Header.Get("Accept"))
		// Forward Authorization (e.g. confidential client credentials) if present.
		if v := r.Header.Get("Authorization"); v != "" {
			req.Header.Set("Authorization", v)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "upstream token endpoint unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// firstAuthorizationServer derives the upstream's primary authorization
// server URL via the same path the mirrored PRM doc uses: fetch the
// upstream PRM, take the first entry of `authorization_servers`. Cached
// alongside the PRM doc.
func (gw *Gateway) firstAuthorizationServer(ctx context.Context, spec *APISpec) (string, error) {
	doc, err := gw.upstreamPRMDoc(ctx, spec)
	if err != nil {
		return "", err
	}
	servers, _ := doc.Raw["authorization_servers"].([]any)
	for _, s := range servers {
		if str, ok := s.(string); ok && str != "" {
			return str, nil
		}
	}
	return "", fmt.Errorf("upstream PRM has no authorization_servers")
}

// fetchUpstreamASMetadata retrieves the upstream's AS metadata document
// from the path-suffix variant URL (RFC 8414 §3.1), tolerant of either
// `/.well-known/oauth-authorization-server<path>` (path-suffix) or
// `<path>/.well-known/oauth-authorization-server` (path-prefix). Tries
// the suffix variant first because that's what most tenanted ASes (e.g.
// auth.atlassian.com) serve.
func fetchUpstreamASMetadata(ctx context.Context, asURL string) (map[string]any, error) {
	u, err := url.Parse(asURL)
	if err != nil {
		return nil, fmt.Errorf("parse AS URL: %w", err)
	}

	path := strings.TrimRight(u.Path, "/")
	candidates := []string{}
	if path == "" {
		candidates = append(candidates,
			fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", u.Scheme, u.Host))
	} else {
		candidates = append(candidates,
			fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server%s", u.Scheme, u.Host, path),
			fmt.Sprintf("%s://%s%s/.well-known/oauth-authorization-server", u.Scheme, u.Host, path))
	}

	var lastErr error
	for _, candidate := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2024-11-05")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			lastErr = fmt.Errorf("AS metadata %s returned %d", candidate, resp.StatusCode)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			lastErr = fmt.Errorf("AS metadata %s decode: %w", candidate, err)
			continue
		}
		return doc, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no AS metadata endpoints tried")
	}
	return nil, lastErr
}
