package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// SupportedProtocolVersions describes the runtime behind this endpoint.
// TT-18004 can extend synthetic support without changing ingress or discovery.
func (s *APISpec) SupportedProtocolVersions() []string {
	if s != nil && (s.IsSyntheticMCPAdapter() || s.IsPairedMCPAdapterProxy()) {
		return mcp.LegacyProtocolVersions()
	}
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
		r.Header.Del("Last-Event-ID")
	}
	if ingress != nil {
		ingress.Validation = mcp.ProtocolValidation{Checked: true}
	}
	return true
}

func (m *JSONRPCMiddleware) writeMCPIngressError(w http.ResponseWriter, r *http.Request, err *mcp.IngressError) {
	var id any
	if ingress := httpctx.GetMCPProtocolContext(r); ingress != nil && ingress.Envelope != nil {
		id = ingress.Envelope.ID
	}
	m.writeJSONRPCError(w, r, id, err.Code, err.Message, err.Data)
}

func rejectModernMCPHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	ingress := httpctx.GetMCPProtocolContext(r)
	if ingress == nil || !ingress.IsModern() || (r.Method != http.MethodGet && r.Method != http.MethodDelete) {
		return false
	}
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return true
}
