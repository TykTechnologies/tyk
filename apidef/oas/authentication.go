package oas

import (
	"fmt"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

type Authentication struct {
	// Enabled makes the API protected when one of the authentication modes is enabled.
	// Old API Definition: `!use_keyless`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not leaked to the upstream.
	// Old API Definition: `strip_auth_data`
	StripAuthorizationData bool `bson:"stripAuthorizationData,omitempty" json:"stripAuthorizationData,omitempty"`
	// BaseIdentityProvider enables multi authentication mechanism and provides the session object that determines rate limits, ACL rules and quotas.
	// It should be set to one of the following:
	// - `auth_token`
	// - `hmac_key`
	// - `basic_auth_user`
	// - `jwt_claim`
	// - `oidc_user`
	// - `oauth_key`
	//
	// Old API Definition: `base_identity_provided_by`
	BaseIdentityProvider apidef.AuthTypeEnum `bson:"baseIdentityProvider,omitempty" json:"baseIdentityProvider,omitempty"`
	// HMAC contains the configurations related to HMAC authentication mode.
	// Old API Definition: `auth_configs["hmac"]`
	HMAC *HMAC `bson:"hmac,omitempty" json:"hmac,omitempty"`
	// OIDC contains the configurations related to OIDC authentication mode.
	// Old API Definition: `auth_configs["oidc"]`
	OIDC *OIDC `bson:"oidc,omitempty" json:"oidc,omitempty"`
	// GoPlugin contains the configurations related to GoPlugin authentication mode.
	GoPlugin *GoPlugin `bson:"goPlugin,omitempty" json:"goPlugin,omitempty"`
	// CustomPlugin contains the configurations related to CustomPlugin authentication mode.
	// Old API Definition: `auth_configs["coprocess"]`
	CustomPlugin    *CustomPlugin   `bson:"customPlugin,omitempty" json:"customPlugin,omitempty"`
	SecuritySchemes SecuritySchemes `bson:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`
}

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

type SecuritySchemes map[string]interface{}

type SecurityScheme interface {
	Import(nativeSS *openapi3.SecurityScheme, enable bool)
}

func (ss SecuritySchemes) Import(name string, nativeSS *openapi3.SecurityScheme, enable bool) error {
	switch {
	case nativeSS.Type == typeApiKey:
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
	case nativeSS.Type == typeHttp && nativeSS.Scheme == schemeBearer && nativeSS.BearerFormat == bearerFormatJWT:
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
	case nativeSS.Type == typeHttp && nativeSS.Scheme == schemeBasic:
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

type AuthSources struct {
	// Header contains configurations of the header auth source, it is enabled by default.
	// Old API Definition:
	Header *AuthSource `bson:"header,omitempty" json:"header,omitempty"`
	// Cookie contains configurations of the cookie auth source.
	// Old API Definition: `api_id`
	Cookie *AuthSource `bson:"cookie,omitempty" json:"cookie,omitempty"`
	// Param contains configurations of the param auth source.
	// Old API Definition: `api_id`
	Query *AuthSource `bson:"query,omitempty" json:"query,omitempty"`
}

func (as *AuthSources) Fill(authConfig apidef.AuthConfig) {
	// Header
	if as.Header == nil {
		as.Header = &AuthSource{}
	}

	as.Header.Fill(!authConfig.DisableHeader, authConfig.AuthHeaderName)
	if ShouldOmit(as.Header) {
		as.Header = nil
	}

	// Query
	if as.Query == nil {
		as.Query = &AuthSource{}
	}

	as.Query.Fill(authConfig.UseParam, authConfig.ParamName)
	if ShouldOmit(as.Query) {
		as.Query = nil
	}

	// Cookie
	if as.Cookie == nil {
		as.Cookie = &AuthSource{}
	}

	as.Cookie.Fill(authConfig.UseCookie, authConfig.CookieName)
	if ShouldOmit(as.Cookie) {
		as.Cookie = nil
	}
}

func (as *AuthSources) ExtractTo(authConfig *apidef.AuthConfig) {
	// Header
	if as.Header != nil {
		var enabled bool
		as.Header.ExtractTo(&enabled, &authConfig.AuthHeaderName)
		authConfig.DisableHeader = !enabled
	} else {
		authConfig.DisableHeader = true
	}

	// Query
	if as.Query != nil {
		as.Query.ExtractTo(&authConfig.UseParam, &authConfig.ParamName)
	}

	// Cookie
	if as.Cookie != nil {
		as.Cookie.ExtractTo(&authConfig.UseCookie, &authConfig.CookieName)
	}
}

type AuthSource struct {
	// Enabled enables the auth source.
	// Old API Definition: `auth_configs[X].use_param/use_cookie`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name is the name of the auth source.
	// Old API Definition: `auth_configs[X].param_name/cookie_name`
	Name string `bson:"name,omitempty" json:"name,omitempty"`
}

func (as *AuthSource) Fill(enabled bool, name string) {
	as.Enabled = enabled
	as.Name = name
}

func (as *AuthSource) ExtractTo(enabled *bool, name *string) {
	*enabled = as.Enabled
	*name = as.Name
}

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

type Scopes struct {
	ClaimName            string          `bson:"claimName,omitempty" json:"claimName,omitempty"`
	ScopeToPolicyMapping []ScopeToPolicy `bson:"scopeToPolicyMapping,omitempty" json:"scopeToPolicyMapping,omitempty"`
}

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

func (s *Scopes) ExtractTo(scopeClaim *apidef.ScopeClaim) {
	scopeClaim.ScopeClaimName = s.ClaimName

	for _, v := range s.ScopeToPolicyMapping {
		if scopeClaim.ScopeToPolicy == nil {
			scopeClaim.ScopeToPolicy = make(map[string]string)
		}

		scopeClaim.ScopeToPolicy[v.Scope] = v.PolicyID
	}
}

type ScopeToPolicy struct {
	Scope    string `bson:"scope,omitempty" json:"scope,omitempty"`
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

type HMAC struct {
	// Enabled enables the HMAC authentication mode.
	// Old API Definition: `enable_signature_checking`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
	// AllowedAlgorithms is the array of HMAC algorithms which are allowed. Tyk supports the following HMAC algorithms:
	// - `hmac-sha1`
	// - `hmac-sha256`
	// - `hmac-sha384`
	// - `hmac-sha512`
	//
	// and reads the value from algorithm header.
	// Old API Definition: `hmac_allowed_algorithms`
	AllowedAlgorithms []string `bson:"allowedAlgorithms,omitempty" json:"allowedAlgorithms,omitempty"`
	// AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
	// The default value is `0`, which deactivates clock skew checks.
	// Old API Definition: `hmac_allowed_clock_skew`
	AllowedClockSkew float64 `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
}

func (h *HMAC) Fill(api apidef.APIDefinition) {
	h.Enabled = api.EnableSignatureChecking

	h.AuthSources.Fill(api.AuthConfigs["hmac"])

	h.AllowedAlgorithms = api.HmacAllowedAlgorithms
	h.AllowedClockSkew = api.HmacAllowedClockSkew
}

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

type OIDC struct {
	// Enabled enables the OIDC authentication mode.
	// Old API Definition: `use_openid`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`

	SegregateByClientId bool       `bson:"segregateByClientId,omitempty" json:"segregateByClientId,omitempty"`
	Providers           []Provider `bson:"providers,omitempty" json:"providers,omitempty"`
	Scopes              *Scopes    `bson:"scopes,omitempty" json:"scopes,omitempty"`
}

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

type Provider struct {
	Issuer                string           `bson:"issuer,omitempty" json:"issuer,omitempty"`
	ClientToPolicyMapping []ClientToPolicy `bson:"clientToPolicyMapping,omitempty" json:"clientToPolicyMapping,omitempty"`
}

type ClientToPolicy struct {
	ClientID string `bson:"clientId,omitempty" json:"clientId,omitempty"`
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

type GoPlugin struct {
	// Enabled enables the GoPlugin authentication mode.
	// Old API Definition: `use_go_plugin_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required
}

func (g *GoPlugin) Fill(api apidef.APIDefinition) {
	g.Enabled = api.UseGoPluginAuth
}

func (g *GoPlugin) ExtractTo(api *apidef.APIDefinition) {
	api.UseGoPluginAuth = g.Enabled
}

type CustomPlugin struct {
	// Enabled enables the CustomPlugin authentication mode.
	// Old API Definition: `enable_coprocess_auth`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
}

func (c *CustomPlugin) Fill(api apidef.APIDefinition) {
	c.Enabled = api.EnableCoProcessAuth

	c.AuthSources.Fill(api.AuthConfigs["coprocess"])
}

func (c *CustomPlugin) ExtractTo(api *apidef.APIDefinition) {
	api.EnableCoProcessAuth = c.Enabled

	authConfig := apidef.AuthConfig{}
	c.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["coprocess"] = authConfig
}
