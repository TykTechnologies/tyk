package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// SupportedProtocolVersions describes the runtime behind this endpoint. Native
// and paired REST-as-MCP endpoints serve the same four Gateway-qualified
// versions once the cached stateless adapter handler is active.
func (s *APISpec) SupportedProtocolVersions() []string {
	return mcp.ServedProtocolVersions()
}

func (m *JSONRPCMiddleware) validateMCPIngress(w http.ResponseWriter, r *http.Request) bool {
	ingress := httpctx.GetMCPProtocolContext(r)
	if err := mcp.ValidateProtocolHeader(r.Header); err != nil {
		m.writeMCPIngressError(w, r, err)
		return false
	}
	modern, err := mcp.ValidateProtocolDeclarations(ingress, m.Spec)
	if err == nil && modern {
		err = mcp.ValidateModernMirroredHeaders(r.Header, ingress.Envelope)
	}
	if err != nil {
		m.writeMCPIngressError(w, r, err)
		return false
	}
	if modern {
		// Removed stateful transport headers cannot affect modern routing/resumption.
		r.Header.Del(mcp.HeaderSessionID)
		r.Header.Del(mcp.HeaderLastEventID)
	}
	if ingress != nil {
		ingress.Validation = mcp.ProtocolValidation{Checked: true}
	}
	return true
}

// requestForMCPAdapterSDK bridges the already validated SEP-2243 Mcp-Name
// representation to the pinned SDK's literal-name comparison. It clones the
// request so the public wire headers and middleware-visible request are never
// rewritten. TT-18011 validation remains the sole decoder and trust boundary.
func requestForMCPAdapterSDK(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}
	ingress := httpctx.GetMCPProtocolContext(r)
	if ingress == nil || !ingress.IsModern() || !ingress.Validation.Checked {
		return r
	}
	raw := r.Header.Get(mcp.HeaderName)
	if raw == "" {
		return r
	}
	decoded, ok := mcp.DecodeMirroredHeader(raw)
	if !ok || decoded == raw {
		return r
	}
	local := r.Clone(r.Context())
	local.Header = r.Header.Clone()
	local.Header.Set(mcp.HeaderName, decoded)
	return local
}

func (m *JSONRPCMiddleware) writeMCPIngressError(w http.ResponseWriter, r *http.Request, err *mcp.IngressError) {
	var id any
	if ingress := httpctx.GetMCPProtocolContext(r); ingress != nil && ingress.Envelope != nil {
		id = ingress.Envelope.ID
	}
	m.writeJSONRPCError(w, r, id, err.Code, err.Message, err.Data)
}

func rejectUnsupportedMCPHTTPMethod(w http.ResponseWriter, r *http.Request, spec *APISpec) bool {
	if r.Method == http.MethodPost || r.Method == http.MethodOptions {
		return false
	}

	ingress := httpctx.GetMCPProtocolContext(r)
	pairedWithoutLegacySession := spec != nil && spec.IsPairedMCPAdapterProxy() && (ingress == nil || !ingress.HasSession)
	if (ingress == nil || !ingress.IsModern()) && !pairedWithoutLegacySession {
		return false
	}
	if ingress != nil {
		ingress.Validation = mcp.ProtocolValidation{Checked: true, HTTPStatus: http.StatusMethodNotAllowed, Message: http.StatusText(http.StatusMethodNotAllowed)}
	}
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return true
}
