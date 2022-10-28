package oas

import (
	"fmt"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

// Authentication types contains configuration about the authentication methods and security policies applied to requests.
type Authentication struct {
	// Enabled makes the API protected when one of the authentication modes is enabled.
	//
	// Tyk native API definition: `!use_keyless`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not leaked to the upstream.
	//
	// Tyk native API definition: `strip_auth_data`.
	StripAuthorizationData bool `bson:"stripAuthorizationData,omitempty" json:"stripAuthorizationData,omitempty"`

	// BaseIdentityProvider enables multi authentication mechanism and provides the session object that determines rate limits, ACL rules and quotas.
	// It should be set to one of the following:
	//
	// - `auth_token`,
	// - `hmac_key`,
	// - `basic_auth_user`,
	// - `jwt_claim`,
	// - `oidc_user`,
	// - `oauth_key`.
	//
	// Tyk native API definition: `base_identity_provided_by`.
	BaseIdentityProvider apidef.AuthTypeEnum `bson:"baseIdentityProvider,omitempty" json:"baseIdentityProvider,omitempty"`

	// HMAC contains the configurations related to HMAC authentication mode.
	//
	// Tyk native API definition: `auth_configs["hmac"]`
	HMAC *HMAC `bson:"hmac,omitempty" json:"hmac,omitempty"`

	// OIDC contains the configurations related to OIDC authentication mode.
	//
	// Tyk native API definition: `auth_configs["oidc"]`
	OIDC *OIDC `bson:"oidc,omitempty" json:"oidc,omitempty"`

	// GoPlugin contains the configurations related to GoPlugin authentication mode.
	GoPlugin *GoPlugin `bson:"goPlugin,omitempty" json:"goPlugin,omitempty"`

	// CustomPlugin contains the configurations related to CustomPlugin authentication mode.
	//
	// Tyk native API definition: `auth_configs["coprocess"]`
	CustomPlugin *CustomPlugin `bson:"customPlugin,omitempty" json:"customPlugin,omitempty"`

	// SecuritySchemes contains security schemes definitions.
	SecuritySchemes SecuritySchemes `bson:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`
}

// Fill fills *Authentication from apidef.APIDefinition.
func (a *Authentication) Fill(api apidef.APIDefinition) {
	a.Enabled = !api.UseKeylessAccess
	a.StripAuthorizationData = api.StripAuthData
	a.BaseIdentityProvider = api.BaseIdentityProvidedBy

	// GoPlugin is at the beginning because it is not dependent to AuthConfigs map.
	if a.GoPlugin == nil {
		a.GoPlugin = &GoPlugin{}
	}

	a.GoPlugin.Fill(api)

	if ShouldOmit(a.GoPlugin) {
		a.GoPlugin = nil
	}

	if api.AuthConfigs == nil || len(api.AuthConfigs) == 0 {
		return
	}

	if _, ok := api.AuthConfigs[apidef.HMACType]; ok {
		if a.HMAC == nil {
			a.HMAC = &HMAC{}
		}

		a.HMAC.Fill(api)
	}

	if ShouldOmit(a.HMAC) {
		a.HMAC = nil
	}

	if _, ok := api.AuthConfigs[apidef.CoprocessType]; ok {
		if a.CustomPlugin == nil {
			a.CustomPlugin = &CustomPlugin{}
		}

		a.CustomPlugin.Fill(api)
	}

	if ShouldOmit(a.CustomPlugin) {
		a.CustomPlugin = nil
	}

	if _, ok := api.AuthConfigs[apidef.OIDCType]; ok {
		if a.OIDC == nil {
			a.OIDC = &OIDC{}
		}

		a.OIDC.Fill(api)
	}

	if ShouldOmit(a.OIDC) {
		a.OIDC = nil
	}
}

// ExtractTo extracts *Authentication into *apidef.APIDefinition.
func (a *Authentication) ExtractTo(api *apidef.APIDefinition) {
	api.UseKeylessAccess = !a.Enabled
	api.StripAuthData = a.StripAuthorizationData
	api.BaseIdentityProvidedBy = a.BaseIdentityProvider

	if a.HMAC != nil {
		a.HMAC.ExtractTo(api)
	}

	if a.OIDC != nil {
		a.OIDC.ExtractTo(api)
	}

	if a.GoPlugin != nil {
		a.GoPlugin.ExtractTo(api)
	}

	if a.CustomPlugin != nil {
		a.CustomPlugin.ExtractTo(api)
	}
}

// SecuritySchemes holds security scheme values, filled with Import().
type SecuritySchemes map[string]interface{}

// SecurityScheme defines an Importer interface for security schemes.
type SecurityScheme interface {
	Import(nativeSS *openapi3.SecurityScheme, enable bool)
}

// Import takes the openapi3.SecurityScheme as argument and applies it to the receiver. The
// SecuritySchemes receiver is a map, so modification of the receiver is enabled, regardless
// of the fact that the receiver isn't a pointer type. The map is a pointer type itself.
func (ss SecuritySchemes) Import(name string, nativeSS *openapi3.SecurityScheme, enable bool) error {
	switch {
	case nativeSS.Type == typeAPIKey:
		token := &Token{}
		if ss[name] == nil {
			ss[name] = token
		} else {
			if tokenVal, ok := ss[name].(*Token); ok {
				token = tokenVal
			} else {
				toStructIfMap(ss[name], token)
			}
		}

		token.Import(nativeSS, enable)
	case nativeSS.Type == typeHTTP && nativeSS.Scheme == schemeBearer && nativeSS.BearerFormat == bearerFormatJWT:
		jwt := &JWT{}
		if ss[name] == nil {
			ss[name] = jwt
		} else {
			if jwtVal, ok := ss[name].(*JWT); ok {
				jwt = jwtVal
			} else {
				toStructIfMap(ss[name], jwt)
			}
		}

		jwt.Import(enable)
	case nativeSS.Type == typeHTTP && nativeSS.Scheme == schemeBasic:
		basic := &Basic{}
		if ss[name] == nil {
			ss[name] = basic
		} else {
			if basicVal, ok := ss[name].(*Basic); ok {
				basic = basicVal
			} else {
				toStructIfMap(ss[name], basic)
			}
		}

		basic.Import(enable)
	case nativeSS.Type == typeOAuth2:
		oauth := &OAuth{}
		if ss[name] == nil {
			ss[name] = oauth
		} else {
			if oauthVal, ok := ss[name].(*OAuth); ok {
				oauth = oauthVal
			} else {
				toStructIfMap(ss[name], oauth)
			}
		}

		oauth.Import(enable)
	default:
		return fmt.Errorf(unsupportedSecuritySchemeFmt, name)
	}

	return nil
}

func baseIdentityProviderPrecedence(authType apidef.AuthTypeEnum) int {
	switch authType {
	case apidef.AuthToken:
		return 1
	case apidef.JWTClaim:
		return 2
	case apidef.OAuthKey:
		return 3
	case apidef.BasicAuthUser:
		return 4
	default:
		return 5
	}
}

// GetBaseIdentityProvider returns the identity provider by precedence from SecuritySchemes.
func (ss SecuritySchemes) GetBaseIdentityProvider() (res apidef.AuthTypeEnum) {
	if len(ss) < 2 {
		return
	}

	resBaseIdentityProvider := baseIdentityProviderPrecedence(apidef.AuthTypeNone)
	res = apidef.OAuthKey

	for _, scheme := range ss {
		if _, ok := scheme.(*Token); ok {
			return apidef.AuthToken
		}

		if _, ok := scheme.(*JWT); ok {
			if baseIdentityProviderPrecedence(apidef.JWTClaim) < resBaseIdentityProvider {
				resBaseIdentityProvider = baseIdentityProviderPrecedence(apidef.JWTClaim)
				res = apidef.JWTClaim
			}
		}
	}

	return
}

// AuthSources defines authentication source configuration: headers, cookies and query parameters.
//
// Tyk native API definition: `auth_configs{}`.
type AuthSources struct {
	// Header contains configurations for the header value auth source, it is enabled by default.
	//
	// Tyk native API definition: `auth_configs[x].header`
	Header *AuthSource `bson:"header,omitempty" json:"header,omitempty"`

	// Cookie contains configurations for the cookie value auth source.
	//
	// Tyk native API definition: `auth_configs[x].cookie`
	Cookie *AuthSource `bson:"cookie,omitempty" json:"cookie,omitempty"`

	// Query contains configurations for the query parameters auth source.
	//
	// Tyk native API definition: `auth_configs[x].query`
	Query *AuthSource `bson:"query,omitempty" json:"query,omitempty"`
}

// Fill fills *AuthSources from apidef.AuthConfig.
func (as *AuthSources) Fill(authConfig apidef.AuthConfig) {
	// Allocate auth sources being filled.
	if as.Header == nil {
		as.Header = &AuthSource{}
	}
	if as.Cookie == nil {
		as.Cookie = &AuthSource{}
	}
	if as.Query == nil {
		as.Query = &AuthSource{}
	}

	// Fill the auth source structures.
	as.Header.Fill(!authConfig.DisableHeader, authConfig.AuthHeaderName)
	as.Query.Fill(authConfig.UseParam, authConfig.ParamName)
	as.Cookie.Fill(authConfig.UseCookie, authConfig.CookieName)

	// Check if auth sources should be omitted as they may be undefined.
	if ShouldOmit(as.Cookie) {
		as.Cookie = nil
	}
	if ShouldOmit(as.Header) {
		as.Header = nil
	}
	if ShouldOmit(as.Query) {
		as.Query = nil
	}
}

// ExtractTo extracts *AuthSources to *apidef.AuthConfig.
func (as *AuthSources) ExtractTo(authConfig *apidef.AuthConfig) {
	// Extract Header auth source.
	if as.Header != nil {
		var enabled bool
		as.Header.ExtractTo(&enabled, &authConfig.AuthHeaderName)
		authConfig.DisableHeader = !enabled
	} else {
		authConfig.DisableHeader = true
	}

	// Extract Query auth source.
	if as.Query != nil {
		as.Query.ExtractTo(&authConfig.UseParam, &authConfig.ParamName)
	}

	// Extract Cookie auth source.
	if as.Cookie != nil {
		as.Cookie.ExtractTo(&authConfig.UseCookie, &authConfig.CookieName)
	}
}

// AuthSource defines an authentication source.
type AuthSource struct {
	// Enabled enables the auth source.
	// Tyk native API definition: `auth_configs[X].use_param/use_cookie`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name is the name of the auth source.
	// Tyk native API definition: `auth_configs[X].param_name/cookie_name`
	Name string `bson:"name,omitempty" json:"name,omitempty"`
}

// Fill fills *AuthSource with values from the parameters.
func (as *AuthSource) Fill(enabled bool, name string) {
	as.Enabled = enabled
	as.Name = name
}

// ExtractTo extracts *AuthSource into the function parameters.
func (as *AuthSource) ExtractTo(enabled *bool, name *string) {
	*enabled = as.Enabled
	*name = as.Name
}

// Signature holds the configuration for signature validation.
type Signature struct {
	Enabled          bool       `bson:"enabled" json:"enabled"` // required
	Algorithm        string     `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	Header           string     `bson:"header,omitempty" json:"header,omitempty"`
	Query            AuthSource `bson:"query,omitempty" json:"query,omitempty"`
	Secret           string     `bson:"secret,omitempty" json:"secret,omitempty"`
	AllowedClockSkew int64      `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
	ErrorCode        int        `bson:"errorCode,omitempty" json:"errorCode,omitempty"`
	ErrorMessage     string     `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
}

// Fill fills *Signature from apidef.AuthConfig.
func (s *Signature) Fill(authConfig apidef.AuthConfig) {
	signature := authConfig.Signature

	s.Enabled = authConfig.ValidateSignature
	s.Algorithm = signature.Algorithm
	s.Header = signature.Header
	s.Query.Fill(signature.UseParam, signature.ParamName)
	s.Secret = signature.Secret
	s.AllowedClockSkew = signature.AllowedClockSkew
	s.ErrorCode = signature.ErrorCode
	s.ErrorMessage = signature.ErrorMessage
}

// ExtractTo extracts *Signature to *apidef.AuthConfig.
func (s *Signature) ExtractTo(authConfig *apidef.AuthConfig) {
	authConfig.ValidateSignature = s.Enabled

	authConfig.Signature.Algorithm = s.Algorithm
	authConfig.Signature.Header = s.Header
	s.Query.ExtractTo(&authConfig.Signature.UseParam, &authConfig.Signature.ParamName)
	authConfig.Signature.Secret = s.Secret
	authConfig.Signature.AllowedClockSkew = s.AllowedClockSkew
	authConfig.Signature.ErrorCode = s.ErrorCode
	authConfig.Signature.ErrorMessage = s.ErrorMessage
}

// Scopes holds the scope to policy mappings for a claim name.
type Scopes struct {
	// ClaimName contains the claim name.
	ClaimName string `bson:"claimName,omitempty" json:"claimName,omitempty"`

	// ScopeToPolicyMapping contains the mappings of scopes to policy IDs.
	ScopeToPolicyMapping []ScopeToPolicy `bson:"scopeToPolicyMapping,omitempty" json:"scopeToPolicyMapping,omitempty"`
}

// Fill fills *Scopes from *apidef.ScopeClaim.
func (s *Scopes) Fill(scopeClaim *apidef.ScopeClaim) {
	s.ClaimName = scopeClaim.ScopeClaimName

	s.ScopeToPolicyMapping = []ScopeToPolicy{}

	for scope, policyID := range scopeClaim.ScopeToPolicy {
		s.ScopeToPolicyMapping = append(s.ScopeToPolicyMapping, ScopeToPolicy{Scope: scope, PolicyID: policyID})
	}

	sort.Slice(s.ScopeToPolicyMapping, func(i, j int) bool {
		return s.ScopeToPolicyMapping[i].Scope < s.ScopeToPolicyMapping[j].Scope
	})

	if len(s.ScopeToPolicyMapping) == 0 {
		s.ScopeToPolicyMapping = nil
	}
}

// ExtractTo extracts *Scopes to *apidef.ScopeClaim.
func (s *Scopes) ExtractTo(scopeClaim *apidef.ScopeClaim) {
	scopeClaim.ScopeClaimName = s.ClaimName

	for _, v := range s.ScopeToPolicyMapping {
		if scopeClaim.ScopeToPolicy == nil {
			scopeClaim.ScopeToPolicy = make(map[string]string)
		}

		scopeClaim.ScopeToPolicy[v.Scope] = v.PolicyID
	}
}

// ScopeToPolicy contains a single scope to policy ID mapping.
type ScopeToPolicy struct {
	// Scope contains the scope name.
	Scope string `bson:"scope,omitempty" json:"scope,omitempty"`

	// PolicyID contains the Policy ID.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

// HMAC holds the configuration for the HMAC authentication mode.
type HMAC struct {
	// Enabled enables the HMAC authentication mode.
	// Tyk native API definition: `enable_signature_checking`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains authentication token source configuration (header, cookie, query).
	AuthSources `bson:",inline" json:",inline"`

	// AllowedAlgorithms is the array of HMAC algorithms which are allowed. Tyk supports the following HMAC algorithms:
	//
	// - `hmac-sha1`
	// - `hmac-sha256`
	// - `hmac-sha384`
	// - `hmac-sha512`
	//
	// and reads the value from algorithm header.
	//
	// Tyk native API definition: `hmac_allowed_algorithms`
	AllowedAlgorithms []string `bson:"allowedAlgorithms,omitempty" json:"allowedAlgorithms,omitempty"`

	// AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
	// The default value is `0`, which deactivates clock skew checks.
	// Tyk native API definition: `hmac_allowed_clock_skew`
	AllowedClockSkew float64 `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
}

// Fill fills *HMAC from apidef.APIDefinition.
func (h *HMAC) Fill(api apidef.APIDefinition) {
	h.Enabled = api.EnableSignatureChecking

	h.AuthSources.Fill(api.AuthConfigs["hmac"])

	h.AllowedAlgorithms = api.HmacAllowedAlgorithms
	h.AllowedClockSkew = api.HmacAllowedClockSkew
}

// ExtractTo extracts *HMAC to *apidef.APIDefinition.
func (h *HMAC) ExtractTo(api *apidef.APIDefinition) {
	api.EnableSignatureChecking = h.Enabled

	authConfig := apidef.AuthConfig{}
	h.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["hmac"] = authConfig

	api.HmacAllowedAlgorithms = h.AllowedAlgorithms
	api.HmacAllowedClockSkew = h.AllowedClockSkew
}

// OIDC contains configuration for the OIDC authentication mode.
type OIDC struct {
	// Enabled enables the OIDC authentication mode.
	//
	// Tyk native API definition: `use_openid`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains authentication token source configuration (header, cookie, query).
	AuthSources `bson:",inline" json:",inline"`

	// SegregateByClientId is a boolean flag. If set to `true, the policies will be applied to a combination of Client ID and User ID.
	//
	// Tyk native API definition: `openid_options.segregate_by_client`.
	SegregateByClientId bool `bson:"segregateByClientId,omitempty" json:"segregateByClientId,omitempty"`

	// Providers contains a list of authorised providers and their Client IDs, and matched policies.
	//
	// Tyk native API definition: `openid_options.providers`.
	Providers []Provider `bson:"providers,omitempty" json:"providers,omitempty"`

	// Scopes contains the defined scope claims.
	Scopes *Scopes `bson:"scopes,omitempty" json:"scopes,omitempty"`
}

// Fill fills *OIDC from apidef.APIDefinition.
func (o *OIDC) Fill(api apidef.APIDefinition) {
	o.Enabled = api.UseOpenID

	o.AuthSources.Fill(api.AuthConfigs["oidc"])

	o.SegregateByClientId = api.OpenIDOptions.SegregateByClient

	o.Providers = []Provider{}
	for _, v := range api.OpenIDOptions.Providers {
		var mapping []ClientToPolicy
		for clientID, polID := range v.ClientIDs {
			mapping = append(mapping, ClientToPolicy{ClientID: clientID, PolicyID: polID})
		}

		if len(mapping) == 0 {
			mapping = nil
		}

		sort.Slice(mapping, func(i, j int) bool {
			return mapping[i].ClientID < mapping[j].ClientID
		})

		o.Providers = append(o.Providers, Provider{Issuer: v.Issuer, ClientToPolicyMapping: mapping})
	}

	if len(o.Providers) == 0 {
		o.Providers = nil
	}

	if o.Scopes == nil {
		o.Scopes = &Scopes{}
	}

	o.Scopes.Fill(&api.Scopes.OIDC)
	if ShouldOmit(o.Scopes) {
		o.Scopes = nil
	}
}

// ExtractTo extracts *OIDC to *apidef.APIDefinition.
func (o *OIDC) ExtractTo(api *apidef.APIDefinition) {
	api.UseOpenID = o.Enabled

	authConfig := apidef.AuthConfig{}
	o.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["oidc"] = authConfig

	api.OpenIDOptions.SegregateByClient = o.SegregateByClientId

	for _, p := range o.Providers {
		clientIDs := make(map[string]string)
		for _, mapping := range p.ClientToPolicyMapping {
			clientIDs[mapping.ClientID] = mapping.PolicyID
		}

		api.OpenIDOptions.Providers = append(api.OpenIDOptions.Providers, apidef.OIDProviderConfig{Issuer: p.Issuer, ClientIDs: clientIDs})
	}

	if o.Scopes != nil {
		o.Scopes.ExtractTo(&api.Scopes.OIDC)
	}
}

// Provider defines an issuer to validate and the Client ID to Policy ID mappings.
type Provider struct {
	// Issuer contains a validation value for the issuer claim, usually a domain name e.g. `accounts.google.com` or similar.
	Issuer string `bson:"issuer,omitempty" json:"issuer,omitempty"`

	// ClientToPolicyMapping contains mappings of Client IDs to Policy IDs.
	ClientToPolicyMapping []ClientToPolicy `bson:"clientToPolicyMapping,omitempty" json:"clientToPolicyMapping,omitempty"`
}

// ClientToPolicy contains a 1-1 mapping between Client ID and Policy ID.
type ClientToPolicy struct {
	// ClientID contains a Client ID.
	ClientID string `bson:"clientId,omitempty" json:"clientId,omitempty"`

	// PolicyID contains a Policy ID.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

// GoPlugin holds confugration related to the Go Plugin authentication mode.
type GoPlugin struct {
	// Enabled enables the GoPlugin authentication mode.
	//
	// Tyk native API definition: `use_go_plugin_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required
}

// Fill fills *GoPlugin from apidef.AuthConfig.
func (g *GoPlugin) Fill(api apidef.APIDefinition) {
	g.Enabled = api.UseGoPluginAuth
}

// ExtractTo extracts *GoPlugin into *apidef.APIDefinition.
func (g *GoPlugin) ExtractTo(api *apidef.APIDefinition) {
	api.UseGoPluginAuth = g.Enabled
}

// CustomPlugin holds configuration for custom plugins.
type CustomPlugin struct {
	// Enabled enables the CustomPlugin authentication mode.
	//
	// Tyk native API definition: `enable_coprocess_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Authentication token sources (header, cookie, query).
	AuthSources `bson:",inline" json:",inline"`
}

// Fill fills *CustomPlugin from apidef.AuthConfig.
func (c *CustomPlugin) Fill(api apidef.APIDefinition) {
	c.Enabled = api.EnableCoProcessAuth

	c.AuthSources.Fill(api.AuthConfigs["coprocess"])
}

// ExtractTo extracts *CustomPlugin to *apidef.APIDefinition.
func (c *CustomPlugin) ExtractTo(api *apidef.APIDefinition) {
	api.EnableCoProcessAuth = c.Enabled

	authConfig := apidef.AuthConfig{}
	c.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["coprocess"] = authConfig
}
