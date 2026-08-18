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

	if m.Spec != nil {
		if configErr := m.Spec.prepareMCPOriginConfig(); configErr != nil {
			return rejectMCPOrigin(w)
		}
		if _, allowed := m.Spec.mcpTrustedOrigins[origin]; allowed {
			return nil, http.StatusOK
		}
	}

	return rejectMCPOrigin(w)
}

func externalOriginForSpec(r *http.Request, spec *APISpec) (string, error) {
	if spec == nil {
		return internalhttputil.ExternalOriginWithTrustedProxies(r, nil)
	}
	if err := spec.prepareMCPOriginConfig(); err != nil {
		return "", err
	}
	return internalhttputil.ExternalOriginWithTrustedProxies(r, spec.mcpTrustedProxyPrefixes)
}

func (spec *APISpec) prepareMCPOriginConfig() error {
	spec.mcpOriginConfigOnce.Do(func() {
		var configuredOrigins []string
		if spec.MCP != nil {
			configuredOrigins = spec.MCP.TrustedOrigins
		}
		origins, err := internalhttputil.CanonicalOrigins(configuredOrigins)
		if err != nil {
			spec.mcpOriginConfigErr = err
			return
		}
		spec.mcpTrustedOrigins = make(map[string]struct{}, len(origins))
		for _, origin := range origins {
			spec.mcpTrustedOrigins[origin] = struct{}{}
		}

		spec.mcpTrustedProxyPrefixes, spec.mcpOriginConfigErr = internalhttputil.ParseTrustedProxyCIDRs(
			spec.GlobalConfig.HttpServerOptions.TrustedProxyCIDRs,
		)
	})
	return spec.mcpOriginConfigErr
}

func rejectMCPOrigin(w http.ResponseWriter) (error, int) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	return nil, middleware.StatusRespond
}
