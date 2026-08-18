package gateway

import (
	"net/http"

	internalhttputil "github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// MCPOriginValidationMiddleware protects MCP endpoints from DNS rebinding and
// cross-origin browser requests before request bodies, credentials, policies,
// or quotas are processed.
type MCPOriginValidationMiddleware struct {
	*BaseMiddleware
}

func (m *MCPOriginValidationMiddleware) Name() string {
	return "MCPOriginValidationMiddleware"
}

func (m *MCPOriginValidationMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCPManaged()
}

// ProcessRequest allows requests without Origin, the API's own public origin,
// and explicitly trusted origins. Invalid origins receive a plain HTTP 403.
//
//nolint:staticcheck // middleware interface requires the status return value
func (m *MCPOriginValidationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	originHeaders := r.Header.Values("Origin")
	if len(originHeaders) == 0 {
		return nil, http.StatusOK
	}
	if len(originHeaders) != 1 {
		return rejectMCPOrigin(w)
	}

	origin, err := internalhttputil.CanonicalOrigin(originHeaders[0])
	if err != nil {
		return rejectMCPOrigin(w)
	}
	external, err := externalOriginForSpec(r, m.Spec)
	if err != nil {
		return rejectMCPOrigin(w)
	}
	if origin == external {
		return nil, http.StatusOK
	}

	if m.Spec.MCP != nil {
		trusted, canonicalErr := internalhttputil.CanonicalOrigins(m.Spec.MCP.TrustedOrigins)
		if canonicalErr != nil {
			return rejectMCPOrigin(w)
		}
		for _, allowed := range trusted {
			if origin == allowed {
				return nil, http.StatusOK
			}
		}
	}

	return rejectMCPOrigin(w)
}

func externalOriginForSpec(r *http.Request, spec *APISpec) (string, error) {
	var trustedProxyCIDRs []string
	if spec != nil {
		trustedProxyCIDRs = spec.GlobalConfig.HttpServerOptions.TrustedProxyCIDRs
	}
	return internalhttputil.ExternalOrigin(r, trustedProxyCIDRs)
}

func rejectMCPOrigin(w http.ResponseWriter) (error, int) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	return nil, middleware.StatusRespond
}
