package oas

import (
	"sort"

	"github.com/lonelycode/osin"

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
	// Token contains the configurations related to standard token based authentication mode.
	// Old API Definition: `auth_configs["authToken"]`
	Token *Token `bson:"token,omitempty" json:"token,omitempty"`
	JWT   *JWT   `bson:"jwt,omitempty" json:"jwt,omitempty"`
	// Basic contains the configurations related to basic authentication mode.
	// Old API Definition: `auth_configs["basic"]`
	Basic *Basic `bson:"basic,omitempty" json:"basic,omitempty"`
	OAuth *OAuth `bson:"oauth,omitempty" json:"oauth,omitempty"`
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
	CustomPlugin    *CustomPlugin          `bson:"customPlugin,omitempty" json:"customPlugin,omitempty"`
	SecuritySchemes map[string]interface{} `bson:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`
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

	if authToken, ok := api.AuthConfigs["authToken"]; ok {
		if a.Token == nil {
			a.Token = &Token{}
		}

		a.Token.Fill(api.UseStandardAuth, authToken)
	}

	if ShouldOmit(a.Token) {
		a.Token = nil
	}

	if _, ok := api.AuthConfigs["jwt"]; ok {
		if a.JWT == nil {
			a.JWT = &JWT{}
		}

		a.JWT.Fill(api)
	}

	if ShouldOmit(a.JWT) {
		a.JWT = nil
	}

	if _, ok := api.AuthConfigs["basic"]; ok {
		if a.Basic == nil {
			a.Basic = &Basic{}
		}

		a.Basic.Fill(api)
	}

	if ShouldOmit(a.Basic) {
		a.Basic = nil
	}

	if _, ok := api.AuthConfigs["oauth"]; ok {
		if a.OAuth == nil {
			a.OAuth = &OAuth{}
		}

		a.OAuth.Fill(api)
	}

	if ShouldOmit(a.OAuth) {
		a.OAuth = nil
	}

	if _, ok := api.AuthConfigs["hmac"]; ok {
		if a.HMAC == nil {
			a.HMAC = &HMAC{}
		}

		a.HMAC.Fill(api)
	}

	if ShouldOmit(a.HMAC) {
		a.HMAC = nil
	}

	if _, ok := api.AuthConfigs["coprocess"]; ok {
		if a.CustomPlugin == nil {
			a.CustomPlugin = &CustomPlugin{}
		}

		a.CustomPlugin.Fill(api)
	}

	if ShouldOmit(a.CustomPlugin) {
		a.CustomPlugin = nil
	}

	if _, ok := api.AuthConfigs["oidc"]; ok {
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

	if a.Token != nil {
		a.Token.ExtractTo(api)
	}

	if a.JWT != nil {
		a.JWT.ExtractTo(api)
	}

	if a.Basic != nil {
		a.Basic.ExtractTo(api)
	}

	if a.OAuth != nil {
		a.OAuth.ExtractTo(api)
	}

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

type Token struct {
	// Enabled enables the token based authentication mode.
	// Old API Definition: `api_id`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
	// EnableClientCertificate allows to create dynamic keys based on certificates.
	// Old API Definition: `auth_configs["authToken"].use_certificate`
	EnableClientCertificate bool `bson:"enableClientCertificate,omitempty" json:"enableClientCertificate,omitempty"`
	//
	// Old API Definition:
	Signature *Signature `bson:"signatureValidation,omitempty" json:"signatureValidation,omitempty"`
}

func (t *Token) Fill(enabled bool, authToken apidef.AuthConfig) {
	t.Enabled = enabled

	// No need to check for emptiness like other optional fields(like Signature below) after filling because it is an inline field.
	t.AuthSources.Fill(authToken)

	t.EnableClientCertificate = authToken.UseCertificate

	if t.Signature == nil {
		t.Signature = &Signature{}
	}

	t.Signature.Fill(authToken)
	if ShouldOmit(t.Signature) {
		t.Signature = nil
	}
}

func (t *Token) ExtractTo(api *apidef.APIDefinition) {
	api.UseStandardAuth = t.Enabled

	authConfig := apidef.AuthConfig{}
	authConfig.UseCertificate = t.EnableClientCertificate

	t.AuthSources.ExtractTo(&authConfig)

	if t.Signature != nil {
		t.Signature.ExtractTo(&authConfig)
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["authToken"] = authConfig
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

type HeaderAuthSource struct {
	// Name is the name of the header which contains the token.
	// Old API Definition: `auth_configs[X].auth_header_name`
	Name string `bson:"name" json:"name"` // required
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

type JWT struct {
	Enabled                 bool `bson:"enabled" json:"enabled"` // required
	AuthSources             `bson:",inline" json:",inline"`
	Source                  string   `bson:"source,omitempty" json:"source,omitempty"`
	SigningMethod           string   `bson:"signingMethod,omitempty" json:"signingMethod,omitempty"`
	IdentityBaseField       string   `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	SkipKid                 bool     `bson:"skipKid,omitempty" json:"skipKid,omitempty"`
	PolicyFieldName         string   `bson:"policyFieldName,omitempty" json:"policyFieldName,omitempty"`
	ClientBaseField         string   `bson:"clientBaseField,omitempty" json:"clientBaseField,omitempty"`
	Scopes                  *Scopes  `bson:"scopes,omitempty" json:"scopes,omitempty"`
	DefaultPolicies         []string `bson:"defaultPolicies,omitempty" json:"defaultPolicies,omitempty"`
	IssuedAtValidationSkew  uint64   `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`
	NotBeforeValidationSkew uint64   `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`
	ExpiresAtValidationSkew uint64   `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`
}

func (j *JWT) Fill(api apidef.APIDefinition) {
	j.AuthSources.Fill(api.AuthConfigs["jwt"])

	j.Enabled = api.EnableJWT
	j.Source = api.JWTSource
	j.SigningMethod = api.JWTSigningMethod
	j.IdentityBaseField = api.JWTIdentityBaseField
	j.SkipKid = api.JWTSkipKid
	j.PolicyFieldName = api.JWTPolicyFieldName
	j.ClientBaseField = api.JWTClientIDBaseField

	if j.Scopes == nil {
		j.Scopes = &Scopes{}
	}

	j.Scopes.Fill(&api.Scopes.JWT)
	if ShouldOmit(j.Scopes) {
		j.Scopes = nil
	}

	j.DefaultPolicies = api.JWTDefaultPolicies
	j.IssuedAtValidationSkew = api.JWTIssuedAtValidationSkew
	j.NotBeforeValidationSkew = api.JWTNotBeforeValidationSkew
	j.ExpiresAtValidationSkew = api.JWTExpiresAtValidationSkew
}

func (j *JWT) ExtractTo(api *apidef.APIDefinition) {
	authConfig := apidef.AuthConfig{}
	j.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["jwt"] = authConfig

	api.EnableJWT = j.Enabled
	api.JWTSource = j.Source
	api.JWTSigningMethod = j.SigningMethod
	api.JWTIdentityBaseField = j.IdentityBaseField
	api.JWTSkipKid = j.SkipKid
	api.JWTPolicyFieldName = j.PolicyFieldName
	api.JWTClientIDBaseField = j.ClientBaseField

	if j.Scopes != nil {
		j.Scopes.ExtractTo(&api.Scopes.JWT)
	}

	api.JWTDefaultPolicies = j.DefaultPolicies
	api.JWTIssuedAtValidationSkew = j.IssuedAtValidationSkew
	api.JWTNotBeforeValidationSkew = j.NotBeforeValidationSkew
	api.JWTExpiresAtValidationSkew = j.ExpiresAtValidationSkew
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

type Basic struct {
	// Enabled enables the basic authentication mode.
	// Old API Definition: `use_basic_auth`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
	// DisableCaching disables the caching of basic authentication key.
	// Old API Definition: `basic_auth.disable_caching`
	DisableCaching bool `bson:"disableCaching,omitempty" json:"disableCaching,omitempty"`
	// CacheTTL is the TTL for a cached basic authentication key in seconds.
	// Old API Definition: `basic_auth.cache_ttl`
	CacheTTL int `bson:"cacheTTL,omitempty" json:"cacheTTL,omitempty"`
	// ExtractCredentialsFromBody helps to extract username and password from body. In some cases, like dealing with SOAP,
	// user credentials can be passed via request body.
	ExtractCredentialsFromBody *ExtractCredentialsFromBody `bson:"extractCredentialsFromBody,omitempty" json:"extractCredentialsFromBody,omitempty"`
}

func (b *Basic) Fill(api apidef.APIDefinition) {
	b.Enabled = api.UseBasicAuth

	b.AuthSources.Fill(api.AuthConfigs["basic"])

	b.DisableCaching = api.BasicAuth.DisableCaching
	b.CacheTTL = api.BasicAuth.CacheTTL

	if b.ExtractCredentialsFromBody == nil {
		b.ExtractCredentialsFromBody = &ExtractCredentialsFromBody{}
	}

	b.ExtractCredentialsFromBody.Fill(api)

	if ShouldOmit(b.ExtractCredentialsFromBody) {
		b.ExtractCredentialsFromBody = nil
	}
}

func (b *Basic) ExtractTo(api *apidef.APIDefinition) {
	api.UseBasicAuth = b.Enabled

	authConfig := apidef.AuthConfig{}
	b.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["basic"] = authConfig

	api.BasicAuth.DisableCaching = b.DisableCaching
	api.BasicAuth.CacheTTL = b.CacheTTL

	if b.ExtractCredentialsFromBody != nil {
		b.ExtractCredentialsFromBody.ExtractTo(api)
	}
}

type ExtractCredentialsFromBody struct {
	// Enabled enables extracting credentials from body.
	// Old API Definition: `basic_auth.extract_from_body`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// UserRegexp is the regex for username e.g. `<User>(.*)</User>`.
	// Old API Definition: `basic_auth.userRegexp`
	UserRegexp string `bson:"userRegexp,omitempty" json:"userRegexp,omitempty"`
	// PasswordRegexp is the regex for password e.g. `<Password>(.*)</Password>`.
	// Old API Definition: `basic_auth.passwordRegexp`
	PasswordRegexp string `bson:"passwordRegexp,omitempty" json:"passwordRegexp,omitempty"`
}

func (e *ExtractCredentialsFromBody) Fill(api apidef.APIDefinition) {
	e.Enabled = api.BasicAuth.ExtractFromBody
	e.UserRegexp = api.BasicAuth.BodyUserRegexp
	e.PasswordRegexp = api.BasicAuth.BodyPasswordRegexp
}

func (e *ExtractCredentialsFromBody) ExtractTo(api *apidef.APIDefinition) {
	api.BasicAuth.ExtractFromBody = e.Enabled
	api.BasicAuth.BodyUserRegexp = e.UserRegexp
	api.BasicAuth.BodyPasswordRegexp = e.PasswordRegexp
}

type OAuth struct {
	Enabled               bool `bson:"enabled" json:"enabled"` // required
	AuthSources           `bson:",inline" json:",inline"`
	AllowedAuthorizeTypes []osin.AuthorizeRequestType `bson:"allowedAuthorizeTypes,omitempty" json:"allowedAuthorizeTypes,omitempty"`
	RefreshToken          bool                        `bson:"refreshToken,omitempty" json:"refreshToken,omitempty"`
	AuthLoginRedirect     string                      `bson:"authLoginRedirect,omitempty" json:"authLoginRedirect,omitempty"`
	Notifications         *Notifications              `bson:"notifications,omitempty" json:"notifications,omitempty"`
}

func (o *OAuth) Fill(api apidef.APIDefinition) {
	o.Enabled = api.UseOauth2

	o.AuthSources.Fill(api.AuthConfigs["oauth"])

	o.AllowedAuthorizeTypes = api.Oauth2Meta.AllowedAuthorizeTypes
	o.AuthLoginRedirect = api.Oauth2Meta.AuthorizeLoginRedirect

	if o.Notifications == nil {
		o.Notifications = &Notifications{}
	}

	o.Notifications.Fill(api.NotificationsDetails)

	if ShouldOmit(o.Notifications) {
		o.Notifications = nil
	}
}

func (o *OAuth) ExtractTo(api *apidef.APIDefinition) {
	api.UseOauth2 = o.Enabled

	authConfig := apidef.AuthConfig{}
	o.AuthSources.ExtractTo(&authConfig)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs["oauth"] = authConfig

	api.Oauth2Meta.AllowedAuthorizeTypes = o.AllowedAuthorizeTypes
	api.Oauth2Meta.AuthorizeLoginRedirect = o.AuthLoginRedirect

	if o.Notifications != nil {
		o.Notifications.ExtractTo(&api.NotificationsDetails)
	}
}

type Notifications struct {
	SharedSecret   string `bson:"sharedSecret,omitempty" json:"sharedSecret,omitempty"`
	OnKeyChangeURL string `bson:"onKeyChangeURL,omitempty" json:"onKeyChangeURL,omitempty"`
}

func (n *Notifications) Fill(nm apidef.NotificationsManager) {
	n.SharedSecret = nm.SharedSecret
	n.OnKeyChangeURL = nm.OAuthKeyChangeURL
}

func (n *Notifications) ExtractTo(nm *apidef.NotificationsManager) {
	nm.SharedSecret = n.SharedSecret
	nm.OAuthKeyChangeURL = n.OnKeyChangeURL
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
