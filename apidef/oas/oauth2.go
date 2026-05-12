package oas

import (
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

// OAuth2 is the container for the new-style OAuth 2.0 security scheme.
// It holds the master Enabled toggle, the AuthSources inheritance from
// the standard Tyk security-scheme contract, and optional sub-blocks
// (currently ScopeCheck) that enable specific OAuth-flow features.
//
// Stored under
// x-tyk-api-gateway.server.authentication.securitySchemes[name].
type OAuth2 struct {
	// Enabled is the master switch for this scheme. When false, the
	// entire oauth2 block is inert.
	Enabled bool `bson:"enabled" json:"enabled"`

	// AuthSources configures where the bearer token is read from
	// (Authorization header by default; cookie / query alternatives).
	AuthSources `bson:",inline" json:",inline"`

	// ScopeCheck enables OAS-native scope enforcement. See
	// OAuth2ScopeCheck for the full configuration contract.
	ScopeCheck *OAuth2ScopeCheck `bson:"scopeCheck,omitempty" json:"scopeCheck,omitempty"`

	// ProtectedResourceMetadata configures the OAuth 2.0 Protected
	// Resource Metadata document (RFC 9728) published for this API.
	// This is the new home for PRM — the deprecated top-level
	// authentication.protectedResourceMetadata block keeps working, but
	// when both are configured this one wins. See OAuth2PRM.
	ProtectedResourceMetadata *OAuth2PRM `bson:"protectedResourceMetadata,omitempty" json:"protectedResourceMetadata,omitempty"`
}

// OAuth2PRM holds the OAuth 2.0 Protected Resource Metadata (RFC 9728)
// configuration for the new-style oauth2 security scheme. It is the
// static counterpart to the deprecated top-level
// authentication.protectedResourceMetadata block; mirror mode (used for
// transparent MCP proxying) stays on the old block.
//
// The `scopes_supported` advertised in the served document is the union
// of:
//   - ScopesSupported (operator-supplied manual additions),
//   - every scope appearing in any alternative of the scheme's
//     scopeCheck.Scopes block (definitionally supported — the gateway
//     enforces them), and
//   - when AutoDeriveScopes is nil or true (the default), every scope
//     declared on the OAS document's per-operation / per-MCP-primitive
//     `security:` arrays for this scheme.
//
// `bearer_methods_supported` is always advertised as ["header"] — Tyk
// only accepts bearer tokens in the Authorization header (RFC 9728 §2).
type OAuth2PRM struct {
	// Enabled activates publishing of the PRM document.
	Enabled bool `bson:"enabled" json:"enabled"`

	// WellKnownPath is the path under the API listen path at which the
	// document is served. Defaults to DefaultPRMWellKnownPath when empty.
	WellKnownPath string `bson:"wellKnownPath,omitempty" json:"wellKnownPath,omitempty"`

	// Resource is the canonical resource identifier this gateway
	// protects. Surfaced as the `resource` field of the PRM document.
	// May contain Tyk context variables, resolved at request time.
	Resource string `bson:"resource,omitempty" json:"resource,omitempty"`

	// AuthorizationServers is the list of issuer URLs published in the
	// PRM document. Clients use these to discover where to obtain a
	// token. At least one entry is required for MCP-proxy APIs.
	AuthorizationServers []string `bson:"authorizationServers,omitempty" json:"authorizationServers,omitempty"`

	// ScopesSupported lets the operator advertise scopes that aren't
	// referenced by any operation's `security:` array (e.g. an
	// audit-only scope). Merged with the scopeCheck.Scopes block and the
	// auto-derived set (see AutoDeriveScopes).
	ScopesSupported []string `bson:"scopesSupported,omitempty" json:"scopesSupported,omitempty"`

	// AutoDeriveScopes toggles auto-derivation of advertised scopes from
	// per-operation / per-MCP-primitive `security:` arrays. When nil or
	// true (the default), declared scopes are added to the PRM
	// `scopes_supported` set automatically. When false, only the
	// operator-supplied ScopesSupported (plus the scopeCheck.Scopes
	// baseline) are advertised — useful for tightly-controlled
	// deployments where every advertised scope must be explicit.
	AutoDeriveScopes *bool `bson:"autoDeriveScopes,omitempty" json:"autoDeriveScopes,omitempty"`
}

// GetWellKnownPath returns the configured well-known path or
// DefaultPRMWellKnownPath when unset. Mirrors the defaulting rule used
// by *ProtectedResourceMetadata so operators reading either struct see
// identical behaviour.
func (prm *OAuth2PRM) GetWellKnownPath() string {
	if prm == nil || prm.WellKnownPath == "" {
		return DefaultPRMWellKnownPath
	}
	return prm.WellKnownPath
}

// IsAutoDeriveScopes reports whether per-operation scope auto-derivation
// is active. The zero value (nil) means enabled — auto-derivation is the
// default; only an explicit false opts out.
func (prm *OAuth2PRM) IsAutoDeriveScopes() bool {
	if prm == nil || prm.AutoDeriveScopes == nil {
		return true
	}
	return *prm.AutoDeriveScopes
}

// OAuth2ScopeCheck holds OAS-native scope enforcement configuration.
//
// Tyk supports three enforcement modes via ScopeSource:
//
//   - "union" (default): require both — the per-operation/primitive
//     `security:` scopes AND the global Scopes alternatives. With
//     Scopes empty (the common case), this collapses to the
//     per-operation model. With Scopes set, every request must
//     additionally satisfy one of the global alternatives.
//   - "operation": the matched OAS operation's or matched MCP
//     primitive's `security:` array drives the required-scope set.
//     Scopes is ignored. Use to opt out of global baselines on a
//     specific API.
//   - "global": ignore per-operation declarations entirely; the
//     Scopes alternatives apply uniformly to every request hitting
//     this API. Useful for "every call needs `api:access`" policies.
//
// Scopes encodes an OR-of-AND grammar: the outer list is OR (any
// satisfied alternative passes); each inner list is AND (every scope
// in that alternative must be present on the token).
type OAuth2ScopeCheck struct {
	Enabled bool `bson:"enabled" json:"enabled"`

	// ClaimNames is the ordered list of JWT claim names to read scopes
	// from. The gateway reads the value of every listed claim that is
	// present on the token, parses each value into individual scopes
	// (per Separator / JSON-array / comma-separated rules), and
	// **merges** the results into one normalized scope set. Scopes
	// alternatives are checked against the merged set — a scope is
	// considered present if it appears in any listed claim.
	//
	// When ClaimNames is empty the gateway uses the default
	// `["scope", "scp"]` so OAuth and OIDC tokens are both honored
	// without operator config. There is no singular ClaimName field —
	// callers always express the source as a list, even when it has
	// one entry.
	ClaimNames []string `bson:"claimNames,omitempty" json:"claimNames,omitempty"`

	// Separator splits the claim's string value into individual
	// scopes. Defaults to a single space (RFC 6749 §3.3). Set to ","
	// for comma-separated IdPs.
	Separator string `bson:"separator,omitempty" json:"separator,omitempty"`

	// ScopeSource selects whether enforcement reads from per-operation
	// `security:`, the global Scopes alternatives, or both. Defaults
	// to "union" — both contribute, Scopes acts as a baseline added
	// to every request.
	ScopeSource string `bson:"scopeSource,omitempty" json:"scopeSource,omitempty"`

	// Scopes is the global OR-of-AND alternative list. The outer list
	// is OR — the caller passes if **any** alternative is satisfied.
	// Each inner list is AND — the token must carry every scope in
	// that alternative for it to be satisfied. Enforced when
	// ScopeSource is "global" or "union" (the default); ignored when
	// ScopeSource is "operation". An empty outer list (or all-empty
	// alternatives) is inert — no enforcement runs.
	Scopes [][]string `bson:"scopes,omitempty" json:"scopes,omitempty"`
}

// ScopeSource constants for OAuth2ScopeCheck.ScopeSource.
const (
	OAuth2ScopeSourceOperation = "operation"
	OAuth2ScopeSourceGlobal    = "global"
	OAuth2ScopeSourceUnion     = "union"
)

// Wire-protocol constants used in WWW-Authenticate challenges and JSON
// failure bodies emitted by the oauth2 middleware.
const (
	// OAuth2ErrInsufficientScope is the RFC 6750 §3.1 error code
	// returned when the token authenticated but lacks scopes required
	// by the request.
	OAuth2ErrInsufficientScope = "insufficient_scope"

	// OAuth2ErrInvalidToken is the RFC 6750 §3.1 error code used when
	// the token cannot be parsed or is otherwise unusable.
	OAuth2ErrInvalidToken = "invalid_token"

	// OAuth2AuthSchemeBearer is the authorization scheme prefix per
	// RFC 6750 §2.1.
	OAuth2AuthSchemeBearer = "Bearer"
)

// HasContent reports whether the OAuth2 block carries operator
// configuration. The master Enabled toggle qualifies, as does any
// configured sub-block (e.g. scopeCheck). Sub-block presence lets the
// map-probe disambiguator distinguish this scheme from a legacy OAuth
// or ExternalOAuth scheme stored as a raw map.
func (o *OAuth2) HasContent() bool {
	if o == nil {
		return false
	}
	if o.Enabled {
		return true
	}
	return o.ScopeCheck != nil || o.ProtectedResourceMetadata != nil
}

// IsEmpty is the inverse of HasContent. Used at fill time to decide
// whether to materialise the OAS-side scheme.
func (o *OAuth2) IsEmpty() bool {
	return !o.HasContent()
}

// fillOAuth2 walks the configured Tyk security schemes and materialises
// any *OAuth2 entries (typed or stored as a raw map after JSON round
// trip) into the public OAS document. Raw maps are recognised by the
// presence of an oauth2 sub-block key (see mapHasOAuth2SubBlock).
func (s *OAS) fillOAuth2() {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return
	}

	for name, scheme := range tykAuth.SecuritySchemes {
		oauth2 := asOAuth2Scheme(scheme)
		if oauth2 == nil {
			continue
		}
		if oauth2.IsEmpty() {
			continue
		}

		// Normalise the cached representation back into the map so
		// future reads return the typed struct.
		tykAuth.SecuritySchemes[name] = oauth2

		// Configured-but-disabled: keep in the Tyk extension so the
		// operator's settings round-trip, but do not advertise the
		// scheme in the public OAS document.
		if !oauth2.Enabled {
			continue
		}

		s.fillOAuth2OASScheme(name, oauth2)
		s.appendSecurity(name)
	}
}

// asOAuth2Scheme returns the typed *OAuth2 view of a raw security
// scheme entry, or nil if the entry is not a new-style oauth2 scheme.
// Distinguishing it from a legacy OAuth / ExternalOAuth map relies on
// the presence of a sub-block key (e.g. scopeCheck). A raw
// `{enabled:true}` map alone is shape-ambiguous with legacy schemes
// and is not recognised here — operators who want the new oauth2
// scheme must configure at least one sub-block.
func asOAuth2Scheme(scheme interface{}) *OAuth2 {
	if scheme == nil {
		return nil
	}
	if v, ok := scheme.(*OAuth2); ok {
		return v
	}
	m, ok := scheme.(map[string]interface{})
	if !ok {
		return nil
	}
	if !mapHasOAuth2SubBlock(m) {
		return nil
	}
	out := &OAuth2{}
	toStructIfMap(m, out)
	return out
}

// mapHasOAuth2SubBlock reports whether a raw scheme map carries a
// new-style oauth2 sub-block. Used by the map-probe disambiguator at
// JSON round-trip time to distinguish the new-style scheme from a
// legacy *OAuth map with no sub-blocks.
//
// IMPORTANT — sub-block keys must be enumerated explicitly. Stories
// 04 (protectedResourceMetadata), 06 (tokenExchange), and 10
// (introspection) add new sub-blocks; each must extend this list so
// JSON round-trips with that sub-block alone (without scopeCheck)
// still type as *OAuth2. Forgetting silently drops the typed view.
func mapHasOAuth2SubBlock(m map[string]interface{}) bool {
	for _, key := range oauth2SubBlockKeys {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

// oauth2SubBlockKeys lists the JSON keys that mark a raw scheme map
// as a new-style oauth2 scheme. Extend when adding a sub-block.
var oauth2SubBlockKeys = []string{
	"scopeCheck",
	"protectedResourceMetadata",
	// "tokenExchange"             — TT-17177 (Story 06)
	// "introspection"             — TT-17187 (Story 10)
}

// fillOAuth2OASScheme materialises the oauth2 OAS Components entry
// for the named scheme.
//
// The OAS spec requires at least one flow on an oauth2 scheme, and
// authorizationCode requires both authorizationUrl and tokenUrl. We
// emit relative paths as placeholders rather than dummy external
// `https://example.com/…` URLs so the saved document doesn't claim
// an unrelated host. Sub-blocks that bring real endpoints (token
// exchange, introspection) override these at materialise time.
//
// The `flows.authorizationCode.scopes` vocabulary is populated from
// the configured scope-check required scopes (so OAS tooling sees
// the same vocabulary the gateway enforces); per-operation
// `security:` declarations land in follow-up extensions.
func (s *OAS) fillOAuth2OASScheme(name string, o *OAuth2) {
	if s.Components == nil {
		s.Components = &openapi3.Components{}
	}
	if s.Components.SecuritySchemes == nil {
		s.Components.SecuritySchemes = make(openapi3.SecuritySchemes)
	}
	scopes := map[string]string{}
	if o != nil && o.ScopeCheck != nil && o.ScopeCheck.Enabled {
		for _, alt := range o.ScopeCheck.Scopes {
			for _, sc := range alt {
				if sc == "" {
					continue
				}
				scopes[sc] = ""
			}
		}
	}
	s.Components.SecuritySchemes[name] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: typeOAuth2,
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "/oauth/authorize",
					TokenURL:         "/oauth/token",
					Scopes:           scopes,
				},
			},
		},
	}
}

// GetTykOAuth2Config returns the typed *OAuth2 configuration for the
// named security scheme, or nil when the scheme is not configured under
// x-tyk-api-gateway as a new-style OAuth2 scheme.
//
// When the scheme entry is still a raw map (post-JSON round-trip and
// pre-fill), this method materialises the typed view via the same
// map-probe used by fillOAuth2 and caches the typed value back into
// the map so subsequent calls are O(1).
func (s *OAS) GetTykOAuth2Config(name string) *OAuth2 {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return nil
	}
	scheme, ok := tykAuth.SecuritySchemes[name]
	if !ok {
		return nil
	}
	oauth2 := asOAuth2Scheme(scheme)
	if oauth2 == nil {
		return nil
	}
	if _, alreadyTyped := scheme.(*OAuth2); !alreadyTyped {
		tykAuth.SecuritySchemes[name] = oauth2
	}
	return oauth2
}

// IsOAuth2Scheme reports whether the named security scheme is a Tyk
// new-style OAuth2 scheme.
func (s *OAS) IsOAuth2Scheme(name string) bool {
	return s.GetTykOAuth2Config(name) != nil
}

// collectOAuth2SchemeNames returns the set of configured OAuth2
// security-scheme names (in the new-style oauth2-block sense).
func (s *OAS) collectOAuth2SchemeNames() map[string]struct{} {
	names := map[string]struct{}{}
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return names
	}
	for name, scheme := range tykAuth.SecuritySchemes {
		if asOAuth2Scheme(scheme) != nil {
			names[name] = struct{}{}
		}
	}
	return names
}

// DeriveOAuth2Scopes returns the set of scopes declared across the OAS
// document's `security:` arrays for every configured oauth2 scheme:
// the root-level `security:`, each path operation's `security:`, and
// every MCP primitive's `security:` (tools, resources, prompts).
// Entries referencing non-oauth2 schemes are ignored. The result is a
// set; callers needing a stable order use SortedOAuth2Scopes.
func (s *OAS) DeriveOAuth2Scopes() map[string]struct{} {
	scopes := map[string]struct{}{}
	oauth2Names := s.collectOAuth2SchemeNames()
	if len(oauth2Names) == 0 {
		return scopes
	}

	collect := func(reqs openapi3.SecurityRequirements) {
		for _, req := range reqs {
			for schemeName, scopeList := range req {
				if _, ok := oauth2Names[schemeName]; !ok {
					continue
				}
				for _, sc := range scopeList {
					if sc == "" {
						continue
					}
					scopes[sc] = struct{}{}
				}
			}
		}
	}

	collect(s.Security)

	if s.Paths != nil {
		for _, pathItem := range s.Paths.Map() {
			if pathItem == nil {
				continue
			}
			for _, op := range pathItem.Operations() {
				if op == nil || op.Security == nil {
					continue
				}
				collect(*op.Security)
			}
		}
	}

	if mw := s.GetTykMiddleware(); mw != nil {
		walk := func(prims MCPPrimitives) {
			for _, prim := range prims {
				if prim == nil {
					continue
				}
				collect(prim.Security)
			}
		}
		walk(mw.McpTools)
		walk(mw.McpResources)
		walk(mw.McpPrompts)
	}

	return scopes
}

// SortedOAuth2Scopes returns DeriveOAuth2Scopes as a sorted, stable
// list. Used to populate read-only "scopes this API advertises"
// previews and the OAS Components security-scheme scope vocabulary.
func (s *OAS) SortedOAuth2Scopes() []string {
	set := s.DeriveOAuth2Scopes()
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// OAuth2PRMScopesSupported returns the sorted `scopes_supported` list to
// advertise in the Protected Resource Metadata document for the named
// oauth2 scheme. It is the union of:
//   - the operator-supplied prm.ScopesSupported list,
//   - every scope appearing in any alternative of the scheme's
//     scopeCheck.Scopes block (the gateway enforces these on every
//     request, so they're definitionally supported), and
//   - when prm.AutoDeriveScopes is nil/true (the default), every scope
//     declared on a per-operation / per-MCP-primitive `security:`
//     array — see DeriveOAuth2Scopes.
//
// Returns nil when the scheme is not a new-style oauth2 scheme or has no
// PRM block configured.
func (s *OAS) OAuth2PRMScopesSupported(schemeName string) []string {
	cfg := s.GetTykOAuth2Config(schemeName)
	if cfg == nil || cfg.ProtectedResourceMetadata == nil {
		return nil
	}
	prm := cfg.ProtectedResourceMetadata

	set := map[string]struct{}{}
	add := func(sc string) {
		if sc != "" {
			set[sc] = struct{}{}
		}
	}

	for _, sc := range prm.ScopesSupported {
		add(sc)
	}
	if cfg.ScopeCheck != nil {
		for _, alt := range cfg.ScopeCheck.Scopes {
			for _, sc := range alt {
				add(sc)
			}
		}
	}
	if prm.IsAutoDeriveScopes() {
		for sc := range s.DeriveOAuth2Scopes() {
			add(sc)
		}
	}

	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for sc := range set {
		out = append(out, sc)
	}
	sort.Strings(out)
	return out
}
