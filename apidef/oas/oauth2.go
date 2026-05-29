package oas

import (
	"fmt"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"

	tyktime "github.com/TykTechnologies/tyk/internal/time"
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

	// ProtectedResourceMetadata configures the RFC 9728 PRM document.
	// New home for PRM; wins over the deprecated top-level
	// authentication.protectedResourceMetadata when both are set.
	ProtectedResourceMetadata *OAuth2PRM `bson:"protectedResourceMetadata,omitempty" json:"protectedResourceMetadata,omitempty"`

	// TokenExchange enables RFC 8693 token exchange. Inbound user
	// tokens are exchanged at the matched provider's IdP for a
	// backend-audienced token before being forwarded upstream. See
	// OAuth2TokenExchange for the full configuration contract.
	TokenExchange *OAuth2TokenExchange `bson:"tokenExchange,omitempty" json:"tokenExchange,omitempty"`
}

// OAuth2PRM configures the RFC 9728 Protected Resource Metadata
// document served for a new-style oauth2 security scheme — the static
// counterpart to the deprecated top-level
// authentication.protectedResourceMetadata block (mirror mode stays on
// the old block). See OAuth2PRMScopesSupported for how the served
// scopes_supported list is assembled.
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

	// AutoDeriveScopes, when nil or true (default), unions the served
	// scopes_supported with scopes from every `security:` array; false
	// advertises only the `flows.<flow>.scopes` catalog. See
	// OAuth2PRMScopesSupported.
	AutoDeriveScopes *bool `bson:"autoDeriveScopes,omitempty" json:"autoDeriveScopes,omitempty"`
}

// GetWellKnownPath returns WellKnownPath, or DefaultPRMWellKnownPath
// when unset.
func (prm *OAuth2PRM) GetWellKnownPath() string {
	if prm == nil || prm.WellKnownPath == "" {
		return DefaultPRMWellKnownPath
	}
	return prm.WellKnownPath
}

// IsAutoDeriveScopes reports whether scope auto-derivation is active.
// Nil (the zero value) means enabled; only an explicit false opts out.
func (prm *OAuth2PRM) IsAutoDeriveScopes() bool {
	if prm == nil || prm.AutoDeriveScopes == nil {
		return true
	}
	return *prm.AutoDeriveScopes
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

// OAuth2TokenExchange holds RFC 8693 token exchange configuration for
// this scheme. When Enabled, the gateway dispatches inbound tokens to
// one of the configured providers based on the inbound `iss` claim and
// posts an RFC 8693 token-exchange request to that provider's
// tokenEndpoint. The exchanged token replaces the Authorization header
// on the request before it is forwarded upstream.
type OAuth2TokenExchange struct {
	// Enabled is the master switch for token exchange on this scheme.
	// When false, the block is inert.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Providers is the list of IdP entries this scheme can exchange
	// against. Provider selection at request time is by inbound `iss`
	// claim match against Providers[i].Issuers — see SelectExchangeProvider
	// in internal/oauth2common.
	Providers []OAuth2TokenExchangeProvider `bson:"providers,omitempty" json:"providers,omitempty"`
}

// OAuth2TokenExchangeProvider configures one IdP entry. Provider selection
// is by inbound `iss` claim match against Issuers; must be unique across Providers.
type OAuth2TokenExchangeProvider struct {
	// Name is an operator-chosen identifier used in audit logs. Unique within Providers.
	Name string `bson:"name" json:"name"`

	// Issuers is the set of inbound token `iss` values routed to this provider.
	// Must not overlap with issuers on other providers — dispatch would be non-deterministic.
	Issuers []string `bson:"issuers,omitempty" json:"issuers,omitempty"`

	// TokenEndpoint is the IdP token endpoint where Tyk POSTs the
	// RFC 8693 exchange request. Must accept
	// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
	TokenEndpoint string `bson:"tokenEndpoint,omitempty" json:"tokenEndpoint,omitempty"`

	// ClientAuth selects how Tyk authenticates as a confidential
	// client to the IdP on the exchange call.
	ClientAuth *OAuth2ClientAuth `bson:"clientAuth,omitempty" json:"clientAuth,omitempty"`

	// DefaultTarget is the fallback target (audience + scopes) used
	// when the matched operation has no per-op exchange override.
	DefaultTarget *OAuth2DefaultTarget `bson:"defaultTarget,omitempty" json:"defaultTarget,omitempty"`

	// Timeout caps each call to TokenEndpoint. Uses Tyk's ReadableDuration ("5s", "100ms").
	// Defaults to 15s when unset.
	Timeout tyktime.ReadableDuration `bson:"timeout,omitempty" json:"timeout,omitempty"`

	// CustomParams are extra form parameters appended to the exchange request.
	// Keys in oauth2ReservedExchangeFormKeys are rejected at API-load time.
	// Values accept env://, secrets://, vault://, consul:// prefixes.
	CustomParams map[string]string `bson:"customParams,omitempty" json:"customParams,omitempty"`
}

// OAuth2ClientAuth describes how Tyk authenticates to the IdP token endpoint.
// ClientSecret accepts env://, secrets://, vault://, consul:// prefixes.
type OAuth2ClientAuth struct {
	// Method selects the client-auth scheme. Supported values:
	//   - "client_secret_basic" (RFC 6749 §2.3.1) — credentials in the
	//     HTTP Authorization header.
	//   - "client_secret_post" (RFC 6749 §2.3.1) — credentials in the
	//     form body.
	// Empty string defaults to client_secret_basic.
	Method   string `bson:"method,omitempty" json:"method,omitempty"`
	ClientID string `bson:"clientId,omitempty" json:"clientId,omitempty"`
	// ClientSecret accepts env://, secrets://, vault://, consul:// prefixes.
	ClientSecret string `bson:"clientSecret,omitempty" json:"clientSecret,omitempty"`
}

// OAuth2DefaultTarget is the fallback audience and scopes when no per-op override is set.
type OAuth2DefaultTarget struct {
	Audience string   `bson:"audience,omitempty" json:"audience,omitempty"`
	Scopes   []string `bson:"scopes,omitempty" json:"scopes,omitempty"`
}

// OAuth2Exchange is the per-operation audience/scopes override for token exchange.
//
// Scope resolution (most-specific wins):
//  1. Enabled=true, Scopes non-empty — explicit per-op list.
//  2. Enabled=true, Scopes empty — inferred from the operation's security: requirement (RFC 8693 §4.5.5).
//  3. provider.DefaultTarget — used when no per-op block is active (Enabled nil or false).
type OAuth2Exchange struct {
	Enabled  *bool    `bson:"enabled,omitempty" json:"enabled,omitempty"`
	Audience string   `bson:"audience,omitempty" json:"audience,omitempty"`
	Scopes   []string `bson:"scopes,omitempty" json:"scopes,omitempty"`
}

// IsActive reports whether this per-op exchange block is active (requires explicit Enabled=true).
func (e *OAuth2Exchange) IsActive() bool {
	return e != nil && e.Enabled != nil && *e.Enabled
}

// InfersScopesFromSecurity reports whether the block uses the inbound security: scopes as fallback.
func (e *OAuth2Exchange) InfersScopesFromSecurity() bool {
	return e != nil && e.Enabled != nil && *e.Enabled && len(e.Scopes) == 0
}

// ScopeSource constants for OAuth2ScopeCheck.ScopeSource.
const (
	OAuth2ScopeSourceOperation = "operation"
	OAuth2ScopeSourceGlobal    = "global"
	OAuth2ScopeSourceUnion     = "union"
)

// Wire-protocol constants for WWW-Authenticate challenges, JSON error bodies,
// and RFC 8693 form fields. Owned here so downstream packages (internal/oauth2common,
// ee/middleware/oauth2tokenexchange) can import them without a circular dependency.
const (
	// RFC 6750 §3.1 error codes.
	OAuth2ErrInsufficientScope = "insufficient_scope"
	OAuth2ErrInvalidToken      = "invalid_token"

	// Token-exchange error codes.
	OAuth2ErrExchangeFailed     = "exchange_failed"
	OAuth2ErrNoMatchingProvider = "no_matching_provider"
	OAuth2ErrMisconfigured      = "misconfigured"

	OAuth2AuthSchemeBearer = "Bearer" // RFC 6750 §2.1

	// RFC 8693 form keys.
	OAuth2FormGrantType           = "grant_type"
	OAuth2FormSubjectToken        = "subject_token"
	OAuth2FormSubjectTokenType    = "subject_token_type"
	OAuth2FormRequestedTokenType  = "requested_token_type"
	OAuth2FormAudience            = "audience"
	OAuth2FormResource            = "resource"
	OAuth2FormScope               = "scope"
	OAuth2FormActorToken          = "actor_token"
	OAuth2FormActorTokenType      = "actor_token_type"
	OAuth2FormClientID            = "client_id"
	OAuth2FormClientSecret        = "client_secret"
	OAuth2FormClientAssertion     = "client_assertion"
	OAuth2FormClientAssertionType = "client_assertion_type"

	// RFC 8693 URNs.
	OAuth2GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	OAuth2TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	OAuth2TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"

	// OAuth2ClientAuth.Method values.
	OAuth2ClientAuthBasic = "client_secret_basic"
	OAuth2ClientAuthPost  = "client_secret_post"

	// JWT standard claim key.
	OAuth2ClaimIss = "iss"

	// OAuth2 response / WWW-Authenticate field names.
	OAuth2FieldError            = "error"
	OAuth2FieldErrorDescription = "error_description"
	OAuth2FieldResourceMetadata = "resource_metadata"

	// Tyk-extended IdP error body fields.
	OAuth2FieldIdpError            = "idp_error"
	OAuth2FieldIdpErrorDescription = "idp_error_description"
)

// oauth2ReservedExchangeFormKeys are RFC 8693 / OAuth2 form parameters Tyk
// sets itself. CustomParams may not shadow them — it would corrupt the wire shape.
var oauth2ReservedExchangeFormKeys = map[string]struct{}{
	OAuth2FormGrantType:           {},
	OAuth2FormSubjectToken:        {},
	OAuth2FormSubjectTokenType:    {},
	OAuth2FormRequestedTokenType:  {},
	OAuth2FormAudience:            {},
	OAuth2FormResource:            {},
	OAuth2FormScope:               {},
	OAuth2FormActorToken:          {},
	OAuth2FormActorTokenType:      {},
	OAuth2FormClientID:            {},
	OAuth2FormClientSecret:        {},
	OAuth2FormClientAssertion:     {},
	OAuth2FormClientAssertionType: {},
}

// ValidateOAuth2Schemes enforces token-exchange invariants across all configured
// oauth2 schemes: non-empty providers when enabled, unique names, no overlapping
// issuers within a scheme, non-empty tokenEndpoint and clientId, no reserved customParams keys.
func (s *OAS) ValidateOAuth2Schemes() error {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return nil
	}
	for name, scheme := range tykAuth.SecuritySchemes {
		cfg := asOAuth2Scheme(scheme)
		if cfg == nil || cfg.IsEmpty() {
			continue
		}
		if err := validateOAuth2TokenExchange(name, cfg.TokenExchange); err != nil {
			return err
		}
	}
	return nil
}

func validateOAuth2TokenExchange(schemeName string, te *OAuth2TokenExchange) error {
	if te == nil || !te.Enabled {
		return nil
	}
	if len(te.Providers) == 0 {
		return fmt.Errorf("oauth2 scheme %q: tokenExchange.enabled is true but providers[] is empty", schemeName)
	}
	seenNames := make(map[string]struct{}, len(te.Providers))
	issuerOwner := make(map[string]string, len(te.Providers))
	for i := range te.Providers {
		p := &te.Providers[i]
		if p.Name == "" {
			return fmt.Errorf("oauth2 scheme %q: tokenExchange.providers[%d].name is required", schemeName, i)
		}
		if _, dup := seenNames[p.Name]; dup {
			return fmt.Errorf("oauth2 scheme %q: duplicate tokenExchange.provider name %q", schemeName, p.Name)
		}
		seenNames[p.Name] = struct{}{}
		if p.TokenEndpoint == "" {
			return fmt.Errorf("oauth2 scheme %q: tokenExchange.provider %q has empty tokenEndpoint", schemeName, p.Name)
		}
		if p.ClientAuth == nil || p.ClientAuth.ClientID == "" {
			return fmt.Errorf("oauth2 scheme %q: tokenExchange.provider %q has empty clientAuth.clientId", schemeName, p.Name)
		}
		for _, iss := range p.Issuers {
			if iss == "" {
				continue
			}
			if owner, dup := issuerOwner[iss]; dup {
				return fmt.Errorf("oauth2 scheme %q: duplicate issuer %q configured on tokenExchange.providers %q and %q", schemeName, iss, owner, p.Name)
			}
			issuerOwner[iss] = p.Name
		}
		for key := range p.CustomParams {
			if _, reserved := oauth2ReservedExchangeFormKeys[key]; reserved {
				return fmt.Errorf("oauth2 scheme %q: tokenExchange.provider %q customParams cannot override reserved RFC 8693 wire key %q", schemeName, p.Name, key)
			}
		}
	}
	return nil
}

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
	return o.ScopeCheck != nil || o.ProtectedResourceMetadata != nil || o.TokenExchange != nil
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
	"protectedResourceMetadata",
	"tokenExchange",
	// "introspection"             — TT-17187 (Story 10)
}

// fillOAuth2OASScheme ensures an OAS Components security-scheme entry
// exists for the named oauth2 scheme. An operator-authored component is
// left untouched; otherwise a minimal skeleton is synthesised to satisfy
// OAS validation (one flow; authorizationCode needs authorizationUrl +
// tokenUrl). Relative placeholder paths avoid claiming an unrelated host.
func (s *OAS) fillOAuth2OASScheme(name string, _ *OAuth2) {
	if s.Components == nil {
		s.Components = &openapi3.Components{}
	}
	if s.Components.SecuritySchemes == nil {
		s.Components.SecuritySchemes = make(openapi3.SecuritySchemes)
	}

	if ref, ok := s.Components.SecuritySchemes[name]; ok && ref != nil && ref.Value != nil {
		return
	}

	s.Components.SecuritySchemes[name] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: typeOAuth2,
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "/oauth/authorize",
					TokenURL:         "/oauth/token",
					Scopes:           map[string]string{},
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

// OAuth2PRMScopesSupported returns the sorted `scopes_supported` list
// for the named oauth2 scheme: the operator-authored `flows.<flow>.scopes`
// catalog, unioned (unless AutoDeriveScopes is false) with every scope
// referenced by a `security:` array — see DeriveOAuth2Scopes. Read-only.
// Returns nil when the scheme has no PRM block or resolves to no scopes.
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

	for sc := range s.oauth2SchemeCatalogScopes(schemeName) {
		add(sc)
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

// oauth2SchemeCatalogScopes returns the scope names declared in the OAS
// security scheme's flow `scopes` maps — the operator-authored
// supported-scopes catalog. Scopes from every configured flow are
// unioned. Returns an empty set when the scheme has no OAS component.
func (s *OAS) oauth2SchemeCatalogScopes(name string) map[string]struct{} {
	out := map[string]struct{}{}
	if s.Components == nil || s.Components.SecuritySchemes == nil {
		return out
	}
	ref, ok := s.Components.SecuritySchemes[name]
	if !ok || ref == nil || ref.Value == nil || ref.Value.Flows == nil {
		return out
	}
	for _, flow := range []*openapi3.OAuthFlow{
		ref.Value.Flows.Implicit,
		ref.Value.Flows.Password,
		ref.Value.Flows.ClientCredentials,
		ref.Value.Flows.AuthorizationCode,
	} {
		if flow == nil {
			continue
		}
		for scope := range flow.Scopes {
			if scope != "" {
				out[scope] = struct{}{}
			}
		}
	}
	return out
}
