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
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

const (
	oauth2DefaultScopeSeparator = " "
	oauth2DefaultScopeClaim     = "scope"
	oauth2FallbackScopeClaim    = "scp"
)

// OAuth2Middleware enforces OAS-native scope checks for the new
// oauth2 security scheme. When scopeCheck is enabled and the
// configured scopeSource reads the OAS root `security:` array, every
// request hitting the API must present a token whose merged scope
// set (across the configured ClaimNames) satisfies at least one
// Security Requirement Object that references the scheme. Per-OAS:
// outer entries are OR-alternatives; scopes within an entry are
// AND-required.
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

	schemeName, cfg := m.Spec.GetOAuth2Config()
	if cfg == nil || cfg.ScopeCheck == nil || !cfg.ScopeCheck.Enabled {
		return nil, http.StatusOK
	}

	alternatives := rootSecurityAlternatives(m.Spec.OAS.Security, schemeName, cfg.ScopeCheck)
	if len(alternatives) == 0 {
		// Root security has nothing to enforce for this scheme.
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

	if !tokenSatisfiesAnyAlternative(claims, cfg.ScopeCheck, alternatives) {
		// First alternative is cited on the challenge — listing every
		// alternative would leak intent (a service-account scope
		// shouldn't be advertised to a user-token caller).
		cited := alternatives[0]
		citedScopes := strings.Join(cited, " ")
		m.fireScopeCheckFailedEvent(r, claims, alternatives, cited, cfg.ScopeCheck)
		m.setWWWAuthenticateInsufficientScope(w, cited)
		body, err := json.Marshal(map[string]interface{}{
			"error":             oas.OAuth2ErrInsufficientScope,
			"error_description": "token does not satisfy required scopes: " + citedScopes,
			"scope":             citedScopes,
		})
		if err != nil {
			m.Logger().WithError(err).Error("oauth2: marshal scope-check response body")
			w.WriteHeader(http.StatusForbidden)
			return nil, middleware.StatusRespond
		}
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write(body); err != nil {
			m.Logger().WithError(err).Debug("oauth2: write scope-check response body")
		}
		return nil, middleware.StatusRespond
	}

	return nil, http.StatusOK
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

// dedupePreserveOrder returns the input slice with empty entries removed
// and duplicates dropped, preserving the declared order of first
// occurrence.
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
