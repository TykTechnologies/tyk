package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// prmResponseDocument represents the OAuth 2.0 Protected Resource Metadata
// response document as defined in RFC 9728.
type prmResponseDocument struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// PRMMiddleware intercepts GET requests to the PRM well-known path and serves
// the OAuth 2.0 Protected Resource Metadata document (RFC 9728).
// It runs after MiddlewareContextVars (so $tyk_context.* is available) but before
// authentication middlewares, allowing the endpoint to be accessed without auth.
type PRMMiddleware struct {
	*BaseMiddleware
}

func (m *PRMMiddleware) Name() string {
	return "PRMMiddleware"
}

func (m *PRMMiddleware) EnabledForSpec() bool {
	return m.Spec.GetPRMConfig() != nil
}

func (m *PRMMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	prm := m.Spec.GetPRMConfig()
	if prm == nil {
		return nil, http.StatusOK // pass through
	}

	// Only intercept GET requests to the well-known path
	if r.Method != http.MethodGet || r.URL.Path != prmWellKnownPath(m.Spec, prm) {
		return nil, http.StatusOK // pass through to next middleware
	}

	// Mirror mode: fetch from upstream, rewrite resource, serve.
	if prm.IsMirrorMode(m.Spec.IsMCP()) {
		if err := m.serveMirroredPRM(w, r, prm); err != nil {
			log.WithError(err).Warn("PRM mirror failed; passing through to upstream")
			return nil, http.StatusOK
		}
		return nil, middleware.StatusRespond
	}

	// Static mode: assemble doc from configured fields.
	resource := prm.Resource
	if resource != "" {
		resource = m.Gw.ReplaceTykVariables(r, resource, false)
	}

	doc := prmResponseDocument{
		Resource:             resource,
		AuthorizationServers: prm.AuthorizationServers,
		ScopesSupported:      prm.ScopesSupported,
	}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.WithError(err).Error("Failed to encode PRM response document")
	}

	return nil, middleware.StatusRespond // terminate chain — response already written
}

// serveMirroredPRM fetches the upstream's PRM doc, rewrites `resource` to
// the gateway URL the client connected to, redirects `authorization_servers`
// at Tyk's per-API AS-proxy URL so RFC 8707 `resource`-parameter rewriting
// can intercept the OAuth flow, and writes the result to w. The fetched
// document is cached per upstream URL with TTL.
func (m *PRMMiddleware) serveMirroredPRM(w http.ResponseWriter, r *http.Request, prm *oas.ProtectedResourceMetadata) error {
	doc, err := m.Gw.upstreamPRMDoc(r.Context(), m.Spec)
	if err != nil {
		return err
	}

	// Rewrite resource to the gateway URL — what the client connected to.
	doc.SetResource(gatewayResourceURL(r, m.Spec))

	// Redirect the AS to Tyk's per-API proxy so we can rewrite the
	// `resource` parameter (RFC 8707) on its way to the upstream AS.
	// Strict authorization servers (Notion) reject the gateway URL as
	// `invalid_target` otherwise.
	doc.Raw["authorization_servers"] = []any{mcpASProxyBaseURL(r, m.Spec)}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		return fmt.Errorf("encode PRM: %w", err)
	}
	return nil
}

// upstreamPRMDoc returns a (cached) clone of the upstream's PRM document
// for the given MCP API. Used by both PRM mirror serving and the AS-proxy
// flow to derive the upstream authorization-server URL. The PRM URL is
// auto-derived from the API's upstream URL via the path-suffix variant
// (RFC 9728 §3.1).
func (gw *Gateway) upstreamPRMDoc(ctx context.Context, spec *APISpec) (*mcp.PRMDocument, error) {
	if spec.GetPRMConfig() == nil {
		return nil, fmt.Errorf("API %q has no PRM config", spec.APIID)
	}
	upstreamPRMURL, err := mcp.DeriveUpstreamPRMURL(spec.Proxy.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("derive upstream PRM URL: %w", err)
	}

	cache := gw.PRMCache()
	if doc, ok := cache.Get(upstreamPRMURL); ok {
		return doc, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	doc, err := mcp.FetchUpstreamPRM(fetchCtx, http.DefaultClient, upstreamPRMURL)
	if err != nil {
		return nil, err
	}
	cache.Put(upstreamPRMURL, doc)
	return doc, nil
}

// gatewayResourceURL builds the URL the MCP client thinks it's talking to:
// scheme + host + the API's listen path. Used as the rewritten `resource`
// field so RFC 9728 §3.3 origin validation passes.
func gatewayResourceURL(r *http.Request, spec *APISpec) string {
	scheme := httputil.RequestScheme(r)
	listen := spec.Proxy.ListenPath
	if !strings.HasSuffix(listen, "/") {
		listen += "/"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, listen)
}

// prmWellKnownPath returns the full well-known path for the PRM endpoint,
// prefixed with the API's listen path.
func prmWellKnownPath(spec *APISpec, prm *oas.ProtectedResourceMetadata) string {
	return path.Join(spec.Proxy.ListenPath, prm.GetWellKnownPath())
}

// setPRMWWWAuthenticateHeader sets the WWW-Authenticate header with a Bearer challenge
// that includes the resource_metadata URL pointing to the PRM well-known endpoint.
// This is a no-op if PRM is not enabled for the API spec.
func setPRMWWWAuthenticateHeader(w http.ResponseWriter, r *http.Request, spec *APISpec) {
	prm := spec.GetPRMConfig()
	if prm == nil {
		return
	}

	metadataURL := fmt.Sprintf("%s://%s%s", httputil.RequestScheme(r), r.Host, prmWellKnownPath(spec, prm))

	w.Header().Set(header.WWWAuthenticate, fmt.Sprintf(`Bearer realm="tyk", resource_metadata="%s"`, metadataURL))
}

// prmError sets the WWW-Authenticate header with PRM metadata and returns
// the given error and status code. This is a convenience wrapper to avoid
// separate setPRMWWWAuthenticateHeader calls at every auth error return site.
func (b *BaseMiddleware) prmError(w http.ResponseWriter, r *http.Request, err error, code int) (error, int) {
	setPRMWWWAuthenticateHeader(w, r, b.Spec)
	return err, code
}

// prmErrorAndStatusCode sets the WWW-Authenticate header with PRM metadata and
// returns the error and status code for the given error type from TykErrors.
func (b *BaseMiddleware) prmErrorAndStatusCode(w http.ResponseWriter, r *http.Request, errType string) (error, int) {
	setPRMWWWAuthenticateHeader(w, r, b.Spec)
	return errorAndStatusCode(errType)
}
