package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
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

	// Only intercept GET requests to the well-known path (include listen path prefix)
	wellKnownPath := path.Join(m.Spec.Proxy.ListenPath, prm.GetWellKnownPath())
	if r.Method != http.MethodGet || r.URL.Path != wellKnownPath {
		return nil, http.StatusOK // pass through to next middleware
	}

	// Resolve context variables in resource field
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

// setPRMWWWAuthenticateHeader sets the WWW-Authenticate header with a Bearer challenge
// that includes the resource_metadata URL pointing to the PRM well-known endpoint.
// This is a no-op if PRM is not enabled for the API spec.
func setPRMWWWAuthenticateHeader(w http.ResponseWriter, r *http.Request, spec *APISpec) {
	prm := spec.GetPRMConfig()
	if prm == nil {
		return
	}

	wellKnownPath := prm.GetWellKnownPath()
	metadataURL := fmt.Sprintf("%s://%s%s", httputil.RequestScheme(r), r.Host, path.Join(spec.Proxy.ListenPath, wellKnownPath))

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
