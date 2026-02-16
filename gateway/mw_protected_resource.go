package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/header"
)

// prmResponseDocument represents the OAuth 2.0 Protected Resource Metadata
// response document as defined in RFC 9728.
type prmResponseDocument struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// loadPRMWellKnownEndpoint registers the PRM well-known endpoint on the subrouter.
// The endpoint is registered directly on the subrouter, which means it is matched
// before the catch-all middleware chain handler (same pattern as loadGraphQLPlayground).
func (gw *Gateway) loadPRMWellKnownEndpoint(spec *APISpec, subrouter *mux.Router) {
	prm := spec.GetPRMConfig()
	if prm == nil {
		return
	}

	wellKnownPath := path.Join("/", prm.GetWellKnownPath())

	subrouter.Methods(http.MethodGet).Path(wellKnownPath).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := prm.Resource
		if resource != "" {
			resource = gw.ReplaceTykVariables(r, resource, false)
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
	})
}

// setPRMWWWAuthenticateHeader sets the WWW-Authenticate header with a Bearer challenge
// that includes the resource_metadata URL pointing to the PRM well-known endpoint.
// This is a no-op if PRM is not enabled for the API spec.
func setPRMWWWAuthenticateHeader(w http.ResponseWriter, r *http.Request, spec *APISpec) {
	prm := spec.GetPRMConfig()
	if prm == nil {
		return
	}

	scheme := "https"
	if proto := r.Header.Get(header.XForwardProto); proto != "" {
		scheme = proto
	} else if r.TLS == nil {
		scheme = "http"
	}

	wellKnownPath := prm.GetWellKnownPath()
	metadataURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, path.Join(spec.Proxy.ListenPath, wellKnownPath))

	w.Header().Set(header.WWWAuthenticate, fmt.Sprintf(`Bearer realm="tyk", resource_metadata="%s"`, metadataURL))
}
