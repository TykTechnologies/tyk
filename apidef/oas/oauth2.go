package oas

import (
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

// OAuth2 is the container for the OAS-native OAuth 2.0 security scheme.
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
}

// OAuth2ScopeCheck holds OAS-native scope enforcement configuration.
//
// The required scopes themselves live in the OAS root `security:`
// array (standard OpenAPI). Each entry in `security:` that lists this
// scheme contributes one alternative; the scopes within an entry are
// AND-required; multiple entries are OR. This sub-block carries only
// the token-side knobs (where to read scopes from the JWT, which
// alternatives to read) — it does not redeclare the scope policy.
//
// Tyk supports three enforcement modes via ScopeSource:
//
//   - "union" (default): per-operation `security:` ∪ root `security:`.
//     With per-operation declarations empty, this collapses to the
//     root-only model. With both set, every request must satisfy at
//     least one alternative drawn from the combined set.
//   - "operation": only the matched OAS operation's `security:` array
//     drives the required-scope set; root `security:` is ignored.
//   - "global": only the OAS root `security:` array applies, uniformly
//     to every request on this API.
type OAuth2ScopeCheck struct {
	// Enabled toggles scope enforcement for this scheme. When false the
	// scope-check sub-block is inert and the oauth2 scheme is treated as
	// authentication-only.
	Enabled bool `bson:"enabled" json:"enabled"`

	// ClaimNames is the ordered list of JWT claim names to read scopes
	// from. The gateway reads the value of every listed claim that is
	// present on the token, parses each value into individual scopes
	// (per Separator / JSON-array / comma-separated rules), and
	// **merges** the results into one normalized scope set. The
	// alternatives drawn from OAS `security:` are checked against the
	// merged set — a scope is considered present if it appears in any
	// listed claim.
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
	// `security:`, the OAS root `security:`, or both. Defaults to
	// "union".
	ScopeSource string `bson:"scopeSource,omitempty" json:"scopeSource,omitempty"`
}

// ScopeCheck toggles the operation-level OAuth 2.0 scope check on an
// operation or MCP primitive. Omitted means enforced; the required
// scopes themselves live in the OAS `security:` array.
type ScopeCheck struct {
	// Enabled enforces the operation's scope check when true. Set it
	// false to exempt the operation (e.g. scopes enforced upstream).
	Enabled bool `bson:"enabled" json:"enabled"`
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
	return o.ScopeCheck != nil
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
// scheme entry, or nil if the entry is not a OAS-native oauth2 scheme.
// Distinguishing it from a legacy OAuth / ExternalOAuth map relies on
// the presence of a sub-block key (e.g. scopeCheck). A raw
// `{enabled:true}` map alone is shape-ambiguous with legacy schemes
// and is not recognised here — operators who want the OAS-native oauth2
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
// OAS-native oauth2 sub-block. Used by the map-probe disambiguator at
// JSON round-trip time to distinguish the OAS-native scheme from a
// legacy *OAuth map with no sub-blocks. Extend oauth2SubBlockKeys
// when adding a sub-block — forgetting silently drops the typed view.
func mapHasOAuth2SubBlock(m map[string]interface{}) bool {
	for _, key := range oauth2SubBlockKeys {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

// oauth2SubBlockKeys lists the JSON keys that mark a raw scheme map
// as a OAS-native oauth2 scheme.
var oauth2SubBlockKeys = []string{
	"scopeCheck",
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
// The `flows.authorizationCode.scopes` vocabulary is aggregated from
// every scope name referenced for this scheme by the OAS root
// `security:` array, so the catalog stays consistent with what the
// gateway enforces. Preserves any existing operator-supplied
// descriptions.
func (s *OAS) fillOAuth2OASScheme(name string, _ *OAuth2) {
	if s.Components == nil {
		s.Components = &openapi3.Components{}
	}
	if s.Components.SecuritySchemes == nil {
		s.Components.SecuritySchemes = make(openapi3.SecuritySchemes)
	}

	existing := map[string]string{}
	if ref, ok := s.Components.SecuritySchemes[name]; ok && ref != nil && ref.Value != nil &&
		ref.Value.Flows != nil && ref.Value.Flows.AuthorizationCode != nil {
		for k, v := range ref.Value.Flows.AuthorizationCode.Scopes {
			existing[k] = v
		}
	}

	scopes := map[string]string{}
	for _, req := range s.Security {
		for _, sc := range req[name] {
			if sc == "" {
				continue
			}
			scopes[sc] = existing[sc]
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
// x-tyk-api-gateway as an OAS-native OAuth2 scheme.
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
// OAS-native OAuth2 scheme.
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

	addOAuth2Scopes(scopes, s.Security, oauth2Names)
	s.addOAuth2ScopesFromPaths(scopes, oauth2Names)
	s.addOAuth2ScopesFromMCPPrimitives(scopes, oauth2Names)

	return scopes
}

// addOAuth2Scopes records every non-empty scope that reqs attaches to a
// recognised oauth2 scheme into scopes.
func addOAuth2Scopes(scopes map[string]struct{}, reqs openapi3.SecurityRequirements, oauth2Names map[string]struct{}) {
	for _, req := range reqs {
		for schemeName, scopeList := range req {
			if _, ok := oauth2Names[schemeName]; !ok {
				continue
			}
			addNonEmptyScopes(scopes, scopeList)
		}
	}
}

// addNonEmptyScopes records each non-empty entry of list into scopes.
func addNonEmptyScopes(scopes map[string]struct{}, list []string) {
	for _, sc := range list {
		if sc != "" {
			scopes[sc] = struct{}{}
		}
	}
}

// addOAuth2ScopesFromPaths collects oauth2 scopes from every path
// operation's `security:` requirement.
func (s *OAS) addOAuth2ScopesFromPaths(scopes map[string]struct{}, oauth2Names map[string]struct{}) {
	if s.Paths == nil {
		return
	}
	for _, pathItem := range s.Paths.Map() {
		if pathItem == nil {
			continue
		}
		for _, op := range pathItem.Operations() {
			if op != nil && op.Security != nil {
				addOAuth2Scopes(scopes, *op.Security, oauth2Names)
			}
		}
	}
}

// addOAuth2ScopesFromMCPPrimitives collects oauth2 scopes from every MCP
// primitive's `security:` requirement (tools, resources, prompts).
func (s *OAS) addOAuth2ScopesFromMCPPrimitives(scopes map[string]struct{}, oauth2Names map[string]struct{}) {
	mw := s.GetTykMiddleware()
	if mw == nil {
		return
	}
	for _, prims := range []MCPPrimitives{mw.McpTools, mw.McpResources, mw.McpPrompts} {
		for _, prim := range prims {
			if prim != nil {
				addOAuth2Scopes(scopes, prim.Security, oauth2Names)
			}
		}
	}
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
