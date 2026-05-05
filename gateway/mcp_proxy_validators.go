package gateway

import (
	"fmt"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// Runtime-state error codes for MCP Proxy admission. Structural codes live in
// apidef/oas/mcp_proxy.go; these are the codes that depend on the gateway's
// in-memory view of loaded APIDefs (apisHandlesByID + APISpec). See RFC §12.2.
const (
	// MCPProxyErrSourceNotLoaded — referenced source APIID is not present in
	// gw.apisHandlesByID at create-time. Without this gate, the loop hop in
	// api_loader.go silently degrades to upstream proxy.
	MCPProxyErrSourceNotLoaded = "source_not_loaded"

	// MCPProxyErrSourceNotMCPCallable — source APIDef does not have
	// Server.AcceptMCPLoopCallers == true.
	MCPProxyErrSourceNotMCPCallable = "source_not_mcp_callable"

	// MCPProxyErrLoopbackSourceRequiresMCPCallerAuthOrKeyless — source has
	// AcceptMCPLoopCallers == false AND uses non-keyless auth: §8.3 strips
	// Authorization on the loop hop, so the source's normal auth would 401.
	MCPProxyErrLoopbackSourceRequiresMCPCallerAuthOrKeyless = "loopback_source_requires_mcp_caller_auth_or_keyless"

	// MCPProxyErrMTLSLoopbackSourceUnsupportedInPoC — CertificateCheckMW
	// 403s the loop hop because no client cert is presented on tyk:// re-entry.
	MCPProxyErrMTLSLoopbackSourceUnsupportedInPoC = "mtls_loopback_source_unsupported_in_poc"

	// MCPProxyErrPartialBackRefState — the back-ref write iteration over
	// source APIDefs failed mid-flight. Operator recovery is to re-save the
	// Proxy (idempotent). See RFC §12.2 atomicity caveat.
	MCPProxyErrPartialBackRefState = "partial_back_ref_state"

	// MCPProxyErrSourceHasDependents — emitted by SourceDeletionGuard when a
	// source APIDef carries a non-empty MCPProxies back-ref (RFC §12.5).
	MCPProxyErrSourceHasDependents = "source_has_dependents"
)

// MCPProxyRuntimeViolation is a single runtime-state admission failure. The
// CRUD handler aggregates a slice of these into a 409 response so the operator
// gets the entire punch list in one round-trip.
type MCPProxyRuntimeViolation struct {
	Code        string `json:"code"`
	SourceAPIID string `json:"source_apiid,omitempty"`
	Message     string `json:"message"`
}

// MCPProxyRuntimeError aggregates runtime-state validation violations.
type MCPProxyRuntimeError struct {
	Violations []MCPProxyRuntimeViolation `json:"violations"`
}

// Error implements error.
func (e *MCPProxyRuntimeError) Error() string {
	if e == nil || len(e.Violations) == 0 {
		return "mcp proxy runtime validation: ok"
	}
	return fmt.Sprintf("mcp proxy runtime validation failed: %d violation(s)", len(e.Violations))
}

// HasViolations reports whether the error contains any violations.
func (e *MCPProxyRuntimeError) HasViolations() bool {
	return e != nil && len(e.Violations) > 0
}

// validateMCPProxyRuntimeState runs the runtime-state subset of the MCP Proxy
// admission rules from RFC §12.2 — the rules that require knowing what's loaded
// in gw.apisHandlesByID. Structural rules live in (*oas.MCPProxy).Validate.
//
// All violations across all sources are accumulated, never short-circuited, so
// the operator sees the full punch list. Returns nil when the spec passes.
func (gw *Gateway) validateMCPProxyRuntimeState(proxy *oas.MCPProxy) *MCPProxyRuntimeError {
	if proxy == nil {
		return nil
	}

	rerr := &MCPProxyRuntimeError{}

	for i := range proxy.Sources {
		src := &proxy.Sources[i]
		if src.BackendMode != "loopback" {
			continue
		}
		if src.SourceAPIID == "" {
			// Already covered by structural validator
			// (loopback_source_missing_source_api_id); skip to avoid double-report.
			continue
		}

		// Admission gate: source APIDef must be loaded.
		if _, ok := gw.apisHandlesByID.Load(src.SourceAPIID); !ok {
			rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
				Code:        MCPProxyErrSourceNotLoaded,
				SourceAPIID: src.SourceAPIID,
				Message:     fmt.Sprintf("source APIID %q is not loaded in this gateway", src.SourceAPIID),
			})
			// Without a loaded spec, no point evaluating further rules on this source.
			continue
		}

		spec := gw.getApiSpec(src.SourceAPIID)
		if spec == nil {
			// Race between Load() and getApiSpec — treat as not_loaded.
			rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
				Code:        MCPProxyErrSourceNotLoaded,
				SourceAPIID: src.SourceAPIID,
				Message:     fmt.Sprintf("source APIID %q vanished between handle and spec lookup", src.SourceAPIID),
			})
			continue
		}

		ext := spec.OAS.GetTykExtension()
		acceptLoop := ext != nil && ext.Server.AcceptMCPLoopCallers

		// AcceptMCPLoopCallers must be true for any loopback source.
		if !acceptLoop {
			rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
				Code:        MCPProxyErrSourceNotMCPCallable,
				SourceAPIID: src.SourceAPIID,
				Message:     fmt.Sprintf("source APIID %q does not have acceptMcpLoopCallers=true", src.SourceAPIID),
			})

			// Sub-rule: AcceptMCPLoopCallers=false combined with non-keyless
			// auth fails harder — §8.3 strips Authorization, so the source's
			// normal auth would 401 every call.
			if !spec.UseKeylessAccess {
				rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
					Code:        MCPProxyErrLoopbackSourceRequiresMCPCallerAuthOrKeyless,
					SourceAPIID: src.SourceAPIID,
					Message:     fmt.Sprintf("source APIID %q has non-keyless auth and acceptMcpLoopCallers=false; loop hop will 401", src.SourceAPIID),
				})
			}
		}

		// mTLS sources cannot be loopback targets in the PoC: CertificateCheckMW
		// 403s the loop hop (no client cert on tyk:// re-entry).
		if spec.UseMutualTLSAuth {
			rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
				Code:        MCPProxyErrMTLSLoopbackSourceUnsupportedInPoC,
				SourceAPIID: src.SourceAPIID,
				Message:     fmt.Sprintf("source APIID %q uses mTLS; loop hop unsupported in PoC", src.SourceAPIID),
			})
		}
	}

	if len(rerr.Violations) == 0 {
		return nil
	}
	return rerr
}

// SourceDeletionGuard returns a non-nil MCPProxyRuntimeError when the given
// source APISpec carries a non-empty Server.MCPProxies back-ref. The single
// violation lists each dependent Proxy APIID so the operator can flip them
// off the source before retrying delete.
//
// Doc: the existing APIDef DELETE handler in gateway/api.go should call this
// helper before proceeding with deletion. Wiring the call site is intentionally
// out of C2's file scope — it's a small follow-up (Phase D or post-PoC). When
// wired, the handler should translate a non-nil result to HTTP 409 and surface
// the Violations slice in the response body.
//
// See RFC §12.5.
func SourceDeletionGuard(spec *APISpec) *MCPProxyRuntimeError {
	if spec == nil {
		return nil
	}
	ext := spec.OAS.GetTykExtension()
	if ext == nil || len(ext.Server.MCPProxies) == 0 {
		return nil
	}
	// One violation per dependent for symmetry with the create-time error shape.
	rerr := &MCPProxyRuntimeError{
		Violations: make([]MCPProxyRuntimeViolation, 0, len(ext.Server.MCPProxies)),
	}
	for _, proxyAPIID := range ext.Server.MCPProxies {
		rerr.Violations = append(rerr.Violations, MCPProxyRuntimeViolation{
			Code:        MCPProxyErrSourceHasDependents,
			SourceAPIID: spec.APIID,
			Message:     fmt.Sprintf("source has dependent MCP Proxy %q; remove from that proxy first", proxyAPIID),
		})
	}
	return rerr
}

// isMCPProxySpec returns true when the loaded APISpec carries the MCPProxy
// extension. This is the distinguishing predicate for the /mcp-proxies route
// surface (separate from APIDefinition.IsMCP, which gates the unrelated
// MCPPrimitive /mcps surface).
func isMCPProxySpec(spec *APISpec) bool {
	if spec == nil {
		return false
	}
	ext := spec.OAS.GetTykExtension()
	return ext != nil && ext.Server.MCPProxy != nil
}
