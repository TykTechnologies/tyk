package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

const (
	oauth2DefaultScopeSeparator = " "
	oauth2DefaultScopeClaim     = "scope"
	oauth2FallbackScopeClaim    = "scp"
)

// OAuth2Middleware enforces OAS-native scope checks for the new
// oauth2 security scheme. When scopeCheck is enabled, the required
// scope set for a request is resolved from the matched OAS operation's
// (or matched MCP primitive's) `security:` array and/or the OAS root
// `security:` array, depending on scopeSource. The request authorizes
// when the token's merged scope set (across the configured ClaimNames)
// satisfies at least one of the resolved OR-of-AND alternatives.
type OAuth2Middleware struct {
	*BaseMiddleware
}

func (m *OAuth2Middleware) Name() string {
	return "OAuth2Middleware"
}

func (m *OAuth2Middleware) EnabledForSpec() bool {
	if m.Spec == nil || !m.Spec.IsOAS {
		return false
	}
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil || ext.Server.Authentication == nil || !ext.Server.Authentication.Enabled {
		return false
	}
	_, cfg := m.Spec.GetOAuth2Config()
	if cfg == nil || !cfg.Enabled {
		return false
	}
	return cfg.ScopeCheck != nil && cfg.ScopeCheck.Enabled
}

func (m *OAuth2Middleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	_, cfg := m.Spec.GetOAuth2Config()
	if cfg == nil || cfg.ScopeCheck == nil || !cfg.ScopeCheck.Enabled {
		return nil, http.StatusOK
	}

	alternatives := m.requiredScopeAlternativesForRequest(r)
	if len(alternatives) == 0 {
		// Nothing to enforce for this request (no per-op `security:`,
		// no root `security:`, or the resolved requirement is vacuous).
		return nil, http.StatusOK
	}

	rawToken := stripBearer(r.Header.Get(header.Authorization))
	if rawToken == "" {
		m.setWWWAuthenticateInsufficientToken(w, oas.OAuth2ErrInvalidToken, "missing bearer token")
		return errors.New("authorization field missing"), http.StatusUnauthorized
	}

	claims, err := oauth2common.ParseUnverifiedClaims(rawToken)
	if err != nil {
		m.setWWWAuthenticateInsufficientToken(w, oas.OAuth2ErrInvalidToken, "token is not a parseable JWT")
		return fmt.Errorf("parsing inbound token claims: %w", err), http.StatusUnauthorized
	}

	if tokenSatisfiesAnyAlternative(claims, cfg.ScopeCheck, alternatives) {
		return nil, http.StatusOK
	}

	// The first declared alternative is cited on the challenge — listing
	// every alternative would leak intent (a service-account scope
	// shouldn't be advertised to a user-token caller).
	cited := alternatives[0]
	citedScopes := strings.Join(cited, " ")
	m.fireScopeCheckFailedEvent(r, claims, alternatives, cited, cfg.ScopeCheck)
	m.setWWWAuthenticateInsufficientScope(w, cited)

	// MCP / JSON-RPC routes get the failure wrapped in a JSON-RPC 2.0
	// error envelope by the chain's error handler (which keys off the
	// routing state). REST routes get the RFC 6750-style JSON body
	// written inline.
	if m.Spec.IsMCP() && httpctx.GetJSONRPCRoutingState(r) != nil {
		return errors.New(oas.OAuth2ErrInsufficientScope), http.StatusForbidden
	}

	body, err := json.Marshal(map[string]interface{}{
		"error":             oas.OAuth2ErrInsufficientScope,
		"error_description": "token does not satisfy required scopes: " + citedScopes,
		"scope":             citedScopes,
	})
	if err != nil {
		m.Logger().WithError(err).Error("failed to marshal scope-check error body")
		return errors.New(oas.OAuth2ErrInsufficientScope), http.StatusForbidden
	}
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		m.Logger().WithError(err).Warning("failed to write scope-check error response")
	}
	return nil, middleware.StatusRespond
}

// requiredScopeAlternativesForRequest resolves the OR-of-AND scope
// requirement for this request. Each inner slice is one AND-group
// (alternative); the request authorizes when at least one alternative
// is fully satisfied. Composition depends on scopeSource:
//
//   - "global": the global Scopes alternatives only; per-op/primitive
//     `security:` is ignored.
//   - "operation": the matched OAS operation's (or matched MCP
//     primitive's) `security:` alternatives only.
//   - "union" (default): both — every request must satisfy at least
//     one per-op alternative AND at least one global alternative. This
//     is expressed as the cross-product (each per-op alternative ANDed
//     with each global alternative). With no per-op `security:`, it
//     collapses to the global list; with no global Scopes, to the
//     per-op list.
//
// An empty AND-group in the resolved set means "this alternative
// requires no oauth2 scope" — that makes the whole requirement
// trivially satisfiable, so nil is returned and the scope-check gate
// (including the missing-token check) is skipped entirely. This is how
// an operation guarded by another scheme (e.g. JWT) coexists with an
// API that also configures oauth2 scope check.
func (m *OAuth2Middleware) requiredScopeAlternativesForRequest(r *http.Request) [][]string {
	schemeName, cfg := m.Spec.GetOAuth2Config()
	if cfg == nil || cfg.ScopeCheck == nil || !cfg.ScopeCheck.Enabled {
		return nil
	}
	source := oauth2ScopeSource(cfg)

	var perOp [][]string
	if source == oas.OAuth2ScopeSourceOperation || source == oas.OAuth2ScopeSourceUnion {
		perOp = m.perOperationScopeAlternatives(r)
	}
	var global [][]string
	if source == oas.OAuth2ScopeSourceGlobal || source == oas.OAuth2ScopeSourceUnion {
		global = rootSecurityAlternatives(m.Spec.OAS.Security, schemeName, cfg.ScopeCheck)
	}

	var combined [][]string
	switch source {
	case oas.OAuth2ScopeSourceGlobal:
		combined = global
	case oas.OAuth2ScopeSourceOperation:
		combined = perOp
	default: // union
		combined = unionScopeAlternatives(perOp, global)
	}

	if len(combined) == 0 {
		return nil
	}
	for _, alt := range combined {
		if len(alt) == 0 {
			// A trivially-satisfiable alternative makes the whole
			// OR-of-AND requirement vacuous.
			return nil
		}
	}
	return combined
}

// perOperationScopeAlternatives gathers the OR-of-AND scope
// alternatives declared on the matched MCP primitive and/or the
// matched OAS REST operation, restricted to this API's oauth2
// scheme(s). An OAS `security:` entry that doesn't reference an oauth2
// scheme contributes the empty AND-group (it's authorized by some
// other scheme), preserving coexistence.
func (m *OAuth2Middleware) perOperationScopeAlternatives(r *http.Request) [][]string {
	oauth2Names := m.oauth2SchemeNames()
	if len(oauth2Names) == 0 {
		return nil
	}

	mw := m.Spec.OAS.GetTykMiddleware()
	var out [][]string

	// MCP primitive scopes — the JSONRPC middleware resolves the
	// primitive name before the auth chain runs and stashes it in the
	// routing state. Non-tools/call methods (e.g. initialize) leave it
	// empty, so no per-primitive enforcement runs for them. A primitive
	// whose scopeCheck is disabled contributes nothing.
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil && state.PrimitiveName != "" && mw != nil {
		// Keyed by type as well as name — tool/resource/prompt names
		// share no namespace, so a same-named primitive of another
		// type must not contribute its scopes here.
		prims := mcpPrimitivesForType(mw, state.PrimitiveType)
		if prim, ok := prims[state.PrimitiveName]; ok && prim != nil && scopeCheckEnabled(prim.ScopeCheck) {
			out = appendOAuth2Alternatives(out, prim.Security, oauth2Names)
		}
	}

	// REST operation `security:` from the matched OAS operation, unless
	// the operation's scopeCheck is disabled.
	if op := m.findOASOperation(r); op != nil && op.Security != nil &&
		scopeCheckEnabled(tykOperationScopeCheck(mw, op.OperationID)) {
		out = appendOAuth2Alternatives(out, *op.Security, oauth2Names)
	}

	return out
}

// mcpPrimitivesForType returns the primitive map matching the routing
// state's primitive type, or nil for a non-primitive method.
func mcpPrimitivesForType(mw *oas.Middleware, primitiveType string) oas.MCPPrimitives {
	switch primitiveType {
	case mcp.PrimitiveTypeTool:
		return mw.McpTools
	case mcp.PrimitiveTypeResource:
		return mw.McpResources
	case mcp.PrimitiveTypePrompt:
		return mw.McpPrompts
	default:
		return nil
	}
}

// scopeCheckEnabled reports whether the operation-level scope check is
// switched on. It is opt-in: the scopeCheck block must be present and
// enabled. An absent block, or enabled:false, leaves it off.
func scopeCheckEnabled(sc *oas.ScopeCheck) bool {
	return sc != nil && sc.Enabled
}

// tykOperationScopeCheck returns the scopeCheck block for the x-tyk
// operation with the given ID, or nil when none is configured.
func tykOperationScopeCheck(mw *oas.Middleware, operationID string) *oas.ScopeCheck {
	if mw == nil || operationID == "" {
		return nil
	}
	if op, ok := mw.Operations[operationID]; ok && op != nil {
		return op.ScopeCheck
	}
	return nil
}

// unionScopeAlternatives combines two OR-of-AND alternative lists for
// scopeSource "union": the request must satisfy at least one per-op
// alternative AND at least one global alternative, which is the
// cross-product (each per-op alternative ANDed with each global
// alternative, per-op scopes first then global, deduplicated). When
// either side is empty the other passes through unchanged.
func unionScopeAlternatives(perOp, global [][]string) [][]string {
	switch {
	case len(perOp) == 0:
		return global
	case len(global) == 0:
		return perOp
	}
	out := make([][]string, 0, len(perOp)*len(global))
	for _, p := range perOp {
		for _, g := range global {
			merged := make([]string, 0, len(p)+len(g))
			merged = append(merged, p...)
			merged = append(merged, g...)
			out = append(out, dedupePreserveOrder(merged))
		}
	}
	return out
}

// appendOAuth2Alternatives converts an OAS SecurityRequirements list
// (OR of alternatives, each AND across schemes) into one AND-group per
// alternative, keeping only the scopes attached to a recognised oauth2
// scheme. Declared scope order is preserved; duplicates are dropped.
func appendOAuth2Alternatives(out [][]string, reqs openapi3.SecurityRequirements, oauth2Names map[string]struct{}) [][]string {
	for _, req := range reqs {
		var alt []string
		for schemeName, scopes := range req {
			if _, ok := oauth2Names[schemeName]; !ok {
				continue
			}
			alt = append(alt, scopes...)
		}
		out = append(out, dedupePreserveOrder(alt))
	}
	return out
}

// oauth2ScopeSource resolves the configured ScopeSource, defaulting to
// "union" (and treating any unrecognised value as "union" — the
// validator rejects bad values at API-load, so this only guards
// runtime defaults).
func oauth2ScopeSource(cfg *oas.OAuth2) string {
	if cfg == nil || cfg.ScopeCheck == nil {
		return oas.OAuth2ScopeSourceUnion
	}
	switch cfg.ScopeCheck.ScopeSource {
	case oas.OAuth2ScopeSourceGlobal, oas.OAuth2ScopeSourceOperation, oas.OAuth2ScopeSourceUnion:
		return cfg.ScopeCheck.ScopeSource
	default:
		return oas.OAuth2ScopeSourceUnion
	}
}

func (m *OAuth2Middleware) oauth2SchemeNames() map[string]struct{} {
	names := map[string]struct{}{}
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil || ext.Server.Authentication == nil {
		return names
	}
	for name := range ext.Server.Authentication.SecuritySchemes {
		if m.Spec.OAS.IsOAuth2Scheme(name) {
			names[name] = struct{}{}
		}
	}
	return names
}

// findOASOperation returns the OAS operation matched for this request
// via the router, or nil. Router-based so path templates resolve.
func (m *OAuth2Middleware) findOASOperation(r *http.Request) *openapi3.Operation {
	route, _ := m.Spec.findOASRoute(r)
	if route == nil {
		return nil
	}
	return route.Operation
}

// rootSecurityAlternatives returns the OR-of-AND list of alternatives
// to enforce, drawn from the OAS root `security:` array. Each entry
// in `security:` that references the named scheme contributes one
// alternative; the scopes within that entry are the AND set. Declared
// order is preserved end-to-end so the operator sees their authored
// form on the failure challenge.
//
// Returns nil when ScopeSource is "operation" — operation-level
// enforcement is handled by a separate middleware. An entry that
// lists the scheme with an empty scope list (the OAS shape for "auth
// required, no specific scope") is preserved as an empty alternative
// — vacuously satisfied, which short-circuits the OR to "pass".
func rootSecurityAlternatives(security openapi3.SecurityRequirements, schemeName string, sc *oas.OAuth2ScopeCheck) [][]string {
	if sc == nil || schemeName == "" {
		return nil
	}
	switch sc.ScopeSource {
	case oas.OAuth2ScopeSourceOperation:
		return nil
	case oas.OAuth2ScopeSourceGlobal, oas.OAuth2ScopeSourceUnion, "":
	default:
		return nil
	}
	out := make([][]string, 0, len(security))
	for _, req := range security {
		scopes, present := req[schemeName]
		if !present {
			continue
		}
		ordered := dedupePreserveOrder(scopes)
		if ordered == nil {
			ordered = []string{}
		}
		out = append(out, ordered)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dedupePreserveOrder returns the input slice with empty entries
// removed and later duplicates dropped, preserving the declared order
// of first occurrence. Returns nil when the result has no elements so
// callers can distinguish "no scopes survived filtering" from a
// well-formed empty alternative.
func dedupePreserveOrder(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// tokenSatisfiesAnyAlternative reports whether the token's merged
// scope set fully covers at least one of the configured alternatives
// (OR-of-AND).
func tokenSatisfiesAnyAlternative(claims jwt.MapClaims, sc *oas.OAuth2ScopeCheck, alternatives [][]string) bool {
	separator := sc.Separator
	if separator == "" {
		separator = oauth2DefaultScopeSeparator
	}
	have := make(map[string]struct{})
	for _, s := range lookupScopes(claims, sc, separator) {
		have[s] = struct{}{}
	}
	for _, alt := range alternatives {
		if alternativeCovered(have, alt) {
			return true
		}
	}
	return false
}

func alternativeCovered(have map[string]struct{}, alt []string) bool {
	for _, want := range alt {
		if _, ok := have[want]; !ok {
			return false
		}
	}
	return true
}

// lookupScopes resolves the token's scope set by reading every
// configured claim name and merging the parsed scope values into one
// deduplicated list. A scope is considered present if it appears in
// any listed claim — there is no precedence between claim names.
func lookupScopes(claims jwt.MapClaims, sc *oas.OAuth2ScopeCheck, separator string) []string {
	seen := map[string]struct{}{}
	merged := make([]string, 0, 4)
	for _, name := range scopeClaimCandidates(sc) {
		for _, s := range extractScopes(claims, name, separator) {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			merged = append(merged, s)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// scopeClaimCandidates returns the ordered list of claim names to read
// scopes from. The operator-supplied ClaimNames list is used verbatim
// when set; otherwise the default `["scope", "scp"]` is returned so
// that OAuth (`scope`) and OIDC / Microsoft Entra (`scp`) tokens are
// both honored without operator config.
func scopeClaimCandidates(sc *oas.OAuth2ScopeCheck) []string {
	if sc != nil && len(sc.ClaimNames) > 0 {
		return sc.ClaimNames
	}
	return []string{oauth2DefaultScopeClaim, oauth2FallbackScopeClaim}
}

func extractScopes(claims jwt.MapClaims, claimName, separator string) []string {
	v, ok := claims[claimName]
	if !ok {
		return nil
	}
	switch tv := v.(type) {
	case string:
		return splitNonEmpty(tv, separator)
	case []interface{}:
		out := make([]string, 0, len(tv))
		for _, e := range tv {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return tv
	}
	return nil
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// setWWWAuthenticate emits an RFC 6750 §3 Bearer challenge with the
// supplied error parameters. Per RFC 6750 §3 the scheme name is
// separated from the auth-params by 1*SP (no comma); auth-params are
// then 1#auth-param (comma-delimited). Parameter order on the wire
// matches the input order — RFC 6750 doesn't constrain it, but
// stability makes assertions easier.
func (m *OAuth2Middleware) setWWWAuthenticate(w http.ResponseWriter, params [][2]string) {
	authParams := make([]string, 0, len(params))
	for _, kv := range params {
		authParams = append(authParams, fmt.Sprintf("%s=%q", kv[0], kv[1]))
	}
	w.Header().Set(header.WWWAuthenticate, oas.OAuth2AuthSchemeBearer+" "+strings.Join(authParams, ", "))
}

// setWWWAuthenticateInsufficientScope emits the RFC 6750 §3.1 challenge
// for a scope-check rejection. The `scope=` parameter advertises the
// required scope set so RFC 6750 / MCP-aware clients can step up.
func (m *OAuth2Middleware) setWWWAuthenticateInsufficientScope(w http.ResponseWriter, scopes []string) {
	scopesValue := strings.Join(scopes, " ")
	m.setWWWAuthenticate(w, [][2]string{
		{"error", oas.OAuth2ErrInsufficientScope},
		{"error_description", "missing required scope: " + scopesValue},
		{"scope", scopesValue},
	})
}

func (m *OAuth2Middleware) setWWWAuthenticateInsufficientToken(w http.ResponseWriter, code, desc string) {
	m.setWWWAuthenticate(w, [][2]string{
		{"error", code},
		{"error_description", desc},
	})
}

// fireScopeCheckFailedEvent emits the OAuth2ScopeCheckFailed audit
// event with non-secret claim identifiers + scope context. Token bytes
// are never emitted. `cited` is the alternative advertised on the
// failure challenge (the first declared alternative); `alternatives`
// is the full OR-of-AND list the request failed against.
func (m *OAuth2Middleware) fireScopeCheckFailedEvent(r *http.Request, claims jwt.MapClaims, alternatives [][]string, cited []string, sc *oas.OAuth2ScopeCheck) {
	separator := oauth2DefaultScopeSeparator
	if sc != nil && sc.Separator != "" {
		separator = sc.Separator
	}
	granted := lookupScopes(claims, sc, separator)
	meta := map[string]interface{}{
		"oauth2_subject_jti":    oauth2common.StringClaim(claims, "jti"),
		"oauth2_subject_azp":    oauth2common.StringClaim(claims, "azp"),
		"required_scopes":       cited,
		"required_alternatives": alternatives,
		"granted_scopes":        granted,
		"path":                  r.URL.Path,
		"method":                r.Method,
		"oauth2_api_id":         m.Spec.APIID,
	}
	m.FireEvent(apidef.TykEvent(event.OAuth2ScopeCheckFailed), meta)
}
