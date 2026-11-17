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
	if m.Spec != nil && m.Spec.IsSyntheticMCPAdapter() {
		if !validMCPAdapterOriginHop(r, m.Gw, m.Spec) {
			return rejectMCPOrigin(w)
		}
		return nil, http.StatusOK
	}
	originHeaders := r.Header.Values("Origin")
	if len(originHeaders) == 0 {
		acceptMCPOrigin(r, m.Spec, "")
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
		acceptMCPOrigin(r, m.Spec, origin)
		return nil, http.StatusOK
	}

	if m.Spec != nil {
		if configErr := m.Spec.prepareMCPOriginConfig(); configErr != nil {
			return rejectMCPOrigin(w)
		}
		if _, allowed := m.Spec.mcpTrustedOrigins[origin]; allowed {
			acceptMCPOrigin(r, m.Spec, origin)
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
		} else if spec.CORS.Enable {
			// CORS wildcards and patterns never confer MCP trust.
			for _, candidate := range spec.CORS.AllowedOrigins {
				if origin, err := internalhttputil.CanonicalOrigin(candidate); err == nil {
					configuredOrigins = append(configuredOrigins, origin)
				}
			}
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

//nolint:staticcheck // middleware helpers use the interface's (error, status) return order.
func rejectMCPOrigin(w http.ResponseWriter) (error, int) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	return nil, middleware.StatusRespond
}
