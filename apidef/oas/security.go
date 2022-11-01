package oas

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	typeAPIKey      = "apiKey"
	typeHTTP        = "http"
	typeOAuth2      = "oauth2"
	schemeBearer    = "bearer"
	schemeBasic     = "basic"
	bearerFormatJWT = "JWT"

	defaultAuthSourceName = "Authorization"

	header = "header"
	query  = "query"
	cookie = "cookie"
)

// Token holds the values related to authentication tokens.
type Token struct {
	// Enabled enables the token based authentication mode.
	//
	// Tyk native API definition: `auth_configs["authToken"].use_standard_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains the configuration for authentication sources.
	AuthSources `bson:",inline" json:",inline"`

	// EnableClientCertificate allows to create dynamic keys based on certificates.
	//
	// Tyk native API definition: `auth_configs["authToken"].use_certificate`
	EnableClientCertificate bool `bson:"enableClientCertificate,omitempty" json:"enableClientCertificate,omitempty"`

	// Signature holds the configuration for verifying the signature of the token.
	//
	// Tyk native API definition: `auth_configs["authToken"].use_certificate`
	Signature *Signature `bson:"signatureValidation,omitempty" json:"signatureValidation,omitempty"`
}

// Import populates *Token from argument values.
func (t *Token) Import(nativeSS *openapi3.SecurityScheme, enable bool) {
	t.Enabled = enable
	t.AuthSources.Import(nativeSS.In)
}

func (s *OAS) fillToken(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillAPIKeyScheme(&authConfig)

	token := &Token{}
	token.Enabled = api.UseStandardAuth
	token.AuthSources.Fill(authConfig)
	token.EnableClientCertificate = authConfig.UseCertificate
	if token.Signature == nil {
		token.Signature = &Signature{}
	}

	token.Signature.Fill(authConfig)
	if ShouldOmit(token.Signature) {
		token.Signature = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = token

	if ShouldOmit(token) {
		delete(s.getTykSecuritySchemes(), authConfig.Name)
	}
}

func (s *OAS) extractTokenTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{DisableHeader: true}

	token := s.getTykTokenAuth(name)
	api.UseStandardAuth = token.Enabled
	authConfig.UseCertificate = token.EnableClientCertificate
	token.AuthSources.ExtractTo(&authConfig)
	if token.Signature != nil {
		token.Signature.ExtractTo(&authConfig)
	}

	s.extractAPIKeySchemeTo(&authConfig, name)

	api.AuthConfigs[apidef.AuthTokenType] = authConfig
}

// JWT holds the configuration for the JWT middleware.
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

// Import populates *JWT based on arguments.
func (j *JWT) Import(enable bool) {
	j.Enabled = enable
	j.Header = &AuthSource{
		Enabled: true,
		Name:    defaultAuthSourceName,
	}
}

func (s *OAS) fillJWT(api apidef.APIDefinition) {
	ac, ok := api.AuthConfigs[apidef.JWTType]
	if !ok || ac.Name == "" {
		return
	}

	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[ac.Name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[ac.Name] = ref
	}

	ref.Value.WithType(typeHTTP).WithScheme(schemeBearer).WithBearerFormat(bearerFormatJWT)

	s.appendSecurity(ac.Name)

	jwt := &JWT{}
	jwt.Enabled = api.EnableJWT
	jwt.AuthSources.Fill(ac)
	jwt.Source = api.JWTSource
	jwt.SigningMethod = api.JWTSigningMethod
	jwt.IdentityBaseField = api.JWTIdentityBaseField
	jwt.SkipKid = api.JWTSkipKid
	jwt.PolicyFieldName = api.JWTPolicyFieldName
	jwt.ClientBaseField = api.JWTClientIDBaseField

	if jwt.Scopes == nil {
		jwt.Scopes = &Scopes{}
	}

	jwt.Scopes.Fill(&api.Scopes.JWT)
	if ShouldOmit(jwt.Scopes) {
		jwt.Scopes = nil
	}

	jwt.DefaultPolicies = api.JWTDefaultPolicies
	jwt.IssuedAtValidationSkew = api.JWTIssuedAtValidationSkew
	jwt.NotBeforeValidationSkew = api.JWTNotBeforeValidationSkew
	jwt.ExpiresAtValidationSkew = api.JWTExpiresAtValidationSkew

	s.getTykSecuritySchemes()[ac.Name] = jwt

	if ShouldOmit(jwt) {
		delete(s.getTykSecuritySchemes(), ac.Name)
	}
}

func (s *OAS) extractJWTTo(api *apidef.APIDefinition, name string) {
	ac := apidef.AuthConfig{Name: name, DisableHeader: true}

	jwt := s.getTykJWTAuth(name)
	api.EnableJWT = jwt.Enabled
	jwt.AuthSources.ExtractTo(&ac)
	api.JWTSource = jwt.Source
	api.JWTSigningMethod = jwt.SigningMethod
	api.JWTIdentityBaseField = jwt.IdentityBaseField
	api.JWTSkipKid = jwt.SkipKid
	api.JWTPolicyFieldName = jwt.PolicyFieldName
	api.JWTClientIDBaseField = jwt.ClientBaseField

	if jwt.Scopes != nil {
		jwt.Scopes.ExtractTo(&api.Scopes.JWT)
	}

	api.JWTDefaultPolicies = jwt.DefaultPolicies
	api.JWTIssuedAtValidationSkew = jwt.IssuedAtValidationSkew
	api.JWTNotBeforeValidationSkew = jwt.NotBeforeValidationSkew
	api.JWTExpiresAtValidationSkew = jwt.ExpiresAtValidationSkew

	api.AuthConfigs[apidef.JWTType] = ac
}

// Basic type holds configuration values related to http basic authentication.
type Basic struct {
	// Enabled enables the basic authentication mode.
	// Tyk native API definition: `use_basic_auth`
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
	// DisableCaching disables the caching of basic authentication key.
	// Tyk native API definition: `basic_auth.disable_caching`
	DisableCaching bool `bson:"disableCaching,omitempty" json:"disableCaching,omitempty"`
	// CacheTTL is the TTL for a cached basic authentication key in seconds.
	// Tyk native API definition: `basic_auth.cache_ttl`
	CacheTTL int `bson:"cacheTTL,omitempty" json:"cacheTTL,omitempty"`
	// ExtractCredentialsFromBody helps to extract username and password from body. In some cases, like dealing with SOAP,
	// user credentials can be passed via request body.
	ExtractCredentialsFromBody *ExtractCredentialsFromBody `bson:"extractCredentialsFromBody,omitempty" json:"extractCredentialsFromBody,omitempty"`
}

// Import populates *Basic from it's arguments.
func (b *Basic) Import(enable bool) {
	b.Enabled = enable
	b.Header = &AuthSource{
		Enabled: true,
		Name:    defaultAuthSourceName,
	}
}

func (s *OAS) fillBasic(api apidef.APIDefinition) {
	ac, ok := api.AuthConfigs[apidef.BasicType]
	if !ok || ac.Name == "" {
		return
	}

	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[ac.Name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[ac.Name] = ref
	}

	ref.Value.WithType(typeHTTP).WithScheme(schemeBasic)

	s.appendSecurity(ac.Name)

	basic := &Basic{}
	basic.Enabled = api.UseBasicAuth
	basic.AuthSources.Fill(ac)
	basic.DisableCaching = api.BasicAuth.DisableCaching
	basic.CacheTTL = api.BasicAuth.CacheTTL

	if basic.ExtractCredentialsFromBody == nil {
		basic.ExtractCredentialsFromBody = &ExtractCredentialsFromBody{}
	}

	basic.ExtractCredentialsFromBody.Fill(api)

	if ShouldOmit(basic.ExtractCredentialsFromBody) {
		basic.ExtractCredentialsFromBody = nil
	}

	s.getTykSecuritySchemes()[ac.Name] = basic

	if ShouldOmit(basic) {
		delete(s.getTykSecuritySchemes(), ac.Name)
	}
}

func (s *OAS) extractBasicTo(api *apidef.APIDefinition, name string) {
	ac := apidef.AuthConfig{Name: name, DisableHeader: true}

	basic := s.getTykBasicAuth(name)
	api.UseBasicAuth = basic.Enabled
	basic.AuthSources.ExtractTo(&ac)
	api.BasicAuth.DisableCaching = basic.DisableCaching
	api.BasicAuth.CacheTTL = basic.CacheTTL

	if basic.ExtractCredentialsFromBody != nil {
		basic.ExtractCredentialsFromBody.ExtractTo(api)
	}

	api.AuthConfigs[apidef.BasicType] = ac
}

// ExtractCredentialsFromBody configures extracting credentials from the request body.
type ExtractCredentialsFromBody struct {
	// Enabled enables extracting credentials from body.
	// Tyk native API definition: `basic_auth.extract_from_body`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// UserRegexp is the regex for username e.g. `<User>(.*)</User>`.
	// Tyk native API definition: `basic_auth.userRegexp`
	UserRegexp string `bson:"userRegexp,omitempty" json:"userRegexp,omitempty"`
	// PasswordRegexp is the regex for password e.g. `<Password>(.*)</Password>`.
	// Tyk native API definition: `basic_auth.passwordRegexp`
	PasswordRegexp string `bson:"passwordRegexp,omitempty" json:"passwordRegexp,omitempty"`
}

// Fill fills *ExtractCredentialsFromBody from apidef.APIDefinition.
func (e *ExtractCredentialsFromBody) Fill(api apidef.APIDefinition) {
	e.Enabled = api.BasicAuth.ExtractFromBody
	e.UserRegexp = api.BasicAuth.BodyUserRegexp
	e.PasswordRegexp = api.BasicAuth.BodyPasswordRegexp
}

// ExtractTo extracts *ExtractCredentialsFromBody and populates *apidef.APIDefinition.
func (e *ExtractCredentialsFromBody) ExtractTo(api *apidef.APIDefinition) {
	api.BasicAuth.ExtractFromBody = e.Enabled
	api.BasicAuth.BodyUserRegexp = e.UserRegexp
	api.BasicAuth.BodyPasswordRegexp = e.PasswordRegexp
}

// OAuth configures the OAuth middleware.
type OAuth struct {
	Enabled               bool `bson:"enabled" json:"enabled"` // required
	AuthSources           `bson:",inline" json:",inline"`
	AllowedAuthorizeTypes []osin.AuthorizeRequestType `bson:"allowedAuthorizeTypes,omitempty" json:"allowedAuthorizeTypes,omitempty"`
	RefreshToken          bool                        `bson:"refreshToken,omitempty" json:"refreshToken,omitempty"`
	AuthLoginRedirect     string                      `bson:"authLoginRedirect,omitempty" json:"authLoginRedirect,omitempty"`
	Notifications         *Notifications              `bson:"notifications,omitempty" json:"notifications,omitempty"`
}

// Import populates *OAuth from it's arguments.
func (o *OAuth) Import(enable bool) {
	o.Enabled = enable
	o.Header = &AuthSource{
		Enabled: true,
		Name:    defaultAuthSourceName,
	}
}

func (s *OAS) fillOAuth(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.OAuthType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillOAuthScheme(api.Oauth2Meta.AllowedAccessTypes, authConfig.Name)

	oauth := &OAuth{}
	oauth.Enabled = api.UseOauth2
	oauth.AuthSources.Fill(authConfig)

	oauth.AllowedAuthorizeTypes = api.Oauth2Meta.AllowedAuthorizeTypes
	oauth.AuthLoginRedirect = api.Oauth2Meta.AuthorizeLoginRedirect

	for _, accessType := range api.Oauth2Meta.AllowedAccessTypes {
		if accessType == osin.REFRESH_TOKEN {
			oauth.RefreshToken = true
			break
		}
	}

	if oauth.Notifications == nil {
		oauth.Notifications = &Notifications{}
	}

	oauth.Notifications.Fill(api.NotificationsDetails)
	if ShouldOmit(oauth.Notifications) {
		oauth.Notifications = nil
	}

	if ShouldOmit(oauth) {
		oauth = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = oauth
}

func (s *OAS) extractOAuthTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{Name: name, DisableHeader: true}

	if oauth := s.getTykOAuthAuth(name); oauth != nil {
		api.UseOauth2 = oauth.Enabled
		oauth.AuthSources.ExtractTo(&authConfig)
		api.Oauth2Meta.AllowedAuthorizeTypes = oauth.AllowedAuthorizeTypes
		api.Oauth2Meta.AuthorizeLoginRedirect = oauth.AuthLoginRedirect
		api.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{}
		if oauth.RefreshToken {
			api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.REFRESH_TOKEN)
		}

		if oauth.Notifications != nil {
			oauth.Notifications.ExtractTo(&api.NotificationsDetails)
		}
	}

	s.extractOAuthSchemeTo(api, name)

	api.AuthConfigs[apidef.OAuthType] = authConfig
}

type OAuthProvider struct {
	JWT           *JWTValidation `bson:"jwt,omitempty" json:"jwt,omitempty"`
	Introspection *Introspection `bson:"introspection,omitempty" json:"introspection,omitempty"`
}

type JWTValidation struct {
	Enabled                 bool   `bson:"enabled" json:"enabled"`
	SigningMethod           string `bson:"signingMethod" json:"signingMethod"`
	Source                  string `bson:"source" json:"source"`
	IdentityBaseField       string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	IssuedAtValidationSkew  uint64 `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`
	NotBeforeValidationSkew uint64 `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`
	ExpiresAtValidationSkew uint64 `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`
}

func (j *JWTValidation) Fill(jwt apidef.JWTValidation) {
	j.Enabled = jwt.Enabled
	j.SigningMethod = jwt.SigningMethod
	j.Source = jwt.Source
	j.IdentityBaseField = jwt.IdentityBaseField
	j.IssuedAtValidationSkew = jwt.IssuedAtValidationSkew
	j.NotBeforeValidationSkew = jwt.NotBeforeValidationSkew
	j.ExpiresAtValidationSkew = jwt.ExpiresAtValidationSkew
}

func (j *JWTValidation) ExtractTo(jwt *apidef.JWTValidation) {
	jwt.Enabled = j.Enabled
	jwt.SigningMethod = j.SigningMethod
	jwt.Source = j.Source
	jwt.IdentityBaseField = j.IdentityBaseField
	jwt.IssuedAtValidationSkew = j.IssuedAtValidationSkew
	jwt.NotBeforeValidationSkew = j.NotBeforeValidationSkew
	jwt.ExpiresAtValidationSkew = j.ExpiresAtValidationSkew
}

type Introspection struct {
	// Enabled enables OAuth access token validation by introspection to a third party.
	Enabled bool `bson:"enabled" json:"enabled"`
	// URL is the URL of the third party provider's introspection endpoint.
	URL string `bson:"url" json:"url"`
	// ClientID is the public identifier for the client, acquired from the third party.
	ClientID string `bson:"clientId" json:"clientId"`
	// ClientSecret is a secret known only to the client and the authorization server, acquired from the third party.
	ClientSecret string `bson:"clientSecret" json:"clientSecret"`
	// IdentityBaseField is the key showing where to find the user id in the claims. If it is empty, the `sub` key is looked at.
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	// Cache is the caching mechanism for introspection responses.
	Cache *IntrospectionCache `bson:"cache" json:"cache"`
}

func (i *Introspection) Fill(intros apidef.Introspection) {
	i.Enabled = intros.Enabled
	i.URL = intros.URL
	i.ClientID = intros.ClientID
	i.ClientSecret = intros.ClientSecret
	i.IdentityBaseField = intros.IdentityBaseField

	if i.Cache == nil {
		i.Cache = &IntrospectionCache{}
	}

	i.Cache.Fill(intros.Cache)
	if ShouldOmit(i.Cache) {
		i.Cache = nil
	}
}

func (i *Introspection) ExtractTo(intros *apidef.Introspection) {
	intros.Enabled = i.Enabled
	intros.URL = i.URL
	intros.ClientID = i.ClientID
	intros.ClientSecret = i.ClientSecret
	intros.IdentityBaseField = i.IdentityBaseField

	if i.Cache != nil {
		i.Cache.ExtractTo(&intros.Cache)
	}
}

type IntrospectionCache struct {
	// Enabled enables the caching mechanism for introspection responses.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Timeout is the duration in seconds of how long the cached value stays.
	// For introspection caching, it is suggested to use a short interval.
	Timeout int64 `bson:"timeout" json:"timeout"`
}

func (c *IntrospectionCache) Fill(cache apidef.IntrospectionCache) {
	c.Enabled = cache.Enabled
	c.Timeout = cache.Timeout
}

func (c *IntrospectionCache) ExtractTo(cache *apidef.IntrospectionCache) {
	cache.Enabled = c.Enabled
	cache.Timeout = c.Timeout
}

type ExternalOAuth struct {
	Enabled     bool `bson:"enabled" json:"enabled"` // required
	AuthSources `bson:",inline" json:",inline"`
	Providers   []OAuthProvider `bson:"providers" json:"providers"` // required
}

func (s *OAS) fillExternalOAuth(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.ExternalOAuthType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillOAuthSchemeForExternal(authConfig.Name)

	externalOAuth := &ExternalOAuth{}
	externalOAuth.Enabled = api.ExternalOAuth.Enabled
	externalOAuth.AuthSources.Fill(authConfig)

	externalOAuth.Providers = make([]OAuthProvider, len(api.ExternalOAuth.Providers))
	for i, provider := range api.ExternalOAuth.Providers {
		p := OAuthProvider{}
		if p.JWT == nil {
			p.JWT = &JWTValidation{}
		}

		p.JWT.Fill(provider.JWT)
		if ShouldOmit(p.JWT) {
			p.JWT = nil
		}

		if p.Introspection == nil {
			p.Introspection = &Introspection{}
		}

		p.Introspection.Fill(provider.Introspection)
		if ShouldOmit(p.Introspection) {
			p.Introspection = nil
		}

		externalOAuth.Providers[i] = p
	}

	if len(externalOAuth.Providers) == 0 {
		externalOAuth.Providers = nil
	}

	if ShouldOmit(externalOAuth) {
		externalOAuth = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = externalOAuth
}

func (s *OAS) extractExternalOAuthTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{Name: name, DisableHeader: true}

	if externalOAuth := s.getTykExternalOAuthAuth(name); externalOAuth != nil {
		api.ExternalOAuth.Enabled = externalOAuth.Enabled
		externalOAuth.AuthSources.ExtractTo(&authConfig)
		api.ExternalOAuth.Providers = make([]apidef.Provider, len(externalOAuth.Providers))
		for i, provider := range externalOAuth.Providers {
			p := apidef.Provider{}

			if provider.JWT != nil {
				provider.JWT.ExtractTo(&p.JWT)
			}

			if provider.Introspection != nil {
				provider.Introspection.ExtractTo(&p.Introspection)
			}

			api.ExternalOAuth.Providers[i] = p
		}
	}

	api.AuthConfigs[apidef.ExternalOAuthType] = authConfig
}

// Notifications holds configuration for updates to keys.
type Notifications struct {
	// SharedSecret is the shared secret used in the notification request.
	SharedSecret string `bson:"sharedSecret,omitempty" json:"sharedSecret,omitempty"`
	// OnKeyChangeURL is the URL a request will be triggered against.
	OnKeyChangeURL string `bson:"onKeyChangeUrl,omitempty" json:"onKeyChangeUrl,omitempty"`
}

// Fill fills *Notifications from apidef.NotificationsManager.
func (n *Notifications) Fill(nm apidef.NotificationsManager) {
	n.SharedSecret = nm.SharedSecret
	n.OnKeyChangeURL = nm.OAuthKeyChangeURL
}

// ExtractTo extracts *Notifications into *apidef.NotificationsManager.
func (n *Notifications) ExtractTo(nm *apidef.NotificationsManager) {
	nm.SharedSecret = n.SharedSecret
	nm.OAuthKeyChangeURL = n.OnKeyChangeURL
}

func (s *OAS) fillSecurity(api apidef.APIDefinition) {
	tykAuthentication := s.GetTykExtension().Server.Authentication
	if tykAuthentication == nil {
		tykAuthentication = &Authentication{}
		s.GetTykExtension().Server.Authentication = tykAuthentication
	}

	if tykAuthentication.SecuritySchemes == nil {
		s.GetTykExtension().Server.Authentication.SecuritySchemes = make(SecuritySchemes)
	}

	tykAuthentication.Fill(api)

	s.fillToken(api)
	s.fillJWT(api)
	s.fillBasic(api)
	s.fillOAuth(api)
	s.fillExternalOAuth(api)

	if len(tykAuthentication.SecuritySchemes) == 0 {
		tykAuthentication.SecuritySchemes = nil
	}

	if ShouldOmit(tykAuthentication) {
		s.GetTykExtension().Server.Authentication = nil
	}
}

func (s *OAS) extractSecurityTo(api *apidef.APIDefinition) {
	if tykAuthentication := s.getTykAuthentication(); tykAuthentication != nil {
		tykAuthentication.ExtractTo(api)
	} else {
		api.UseKeylessAccess = true
		return
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	if len(s.Security) == 0 || len(s.Components.SecuritySchemes) == 0 {
		return
	}

	for schemeName := range s.getTykSecuritySchemes() {
		if _, ok := s.Security[0][schemeName]; ok {
			v := s.Components.SecuritySchemes[schemeName].Value
			switch {
			case v.Type == typeAPIKey:
				s.extractTokenTo(api, schemeName)
			case v.Type == typeHTTP && v.Scheme == schemeBearer && v.BearerFormat == bearerFormatJWT:
				s.extractJWTTo(api, schemeName)
			case v.Type == typeHTTP && v.Scheme == schemeBasic:
				s.extractBasicTo(api, schemeName)
			case v.Type == typeOAuth2:
				securityScheme := s.getTykSecurityScheme(schemeName)
				if securityScheme == nil {
					return
				}

				externalOAuth := &ExternalOAuth{}
				if oauthVal, ok := securityScheme.(*ExternalOAuth); ok {
					externalOAuth = oauthVal
				} else {
					toStructIfMap(securityScheme, externalOAuth)
				}

				if len(externalOAuth.Providers) > 0 {
					s.extractExternalOAuthTo(api, schemeName)
				} else {
					s.extractOAuthTo(api, schemeName)
				}
			}
		}
	}
}

func (s *OAS) fillAPIKeyScheme(ac *apidef.AuthConfig) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[ac.Name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[ac.Name] = ref
	}

	var loc, key string

	switch {
	case ref.Value.In == header || (ref.Value.In == "" && !ac.DisableHeader):
		loc = header
		key = ac.AuthHeaderName
		ac.AuthHeaderName = ""
		ac.DisableHeader = true
	case ref.Value.In == query || (ref.Value.In == "" && ac.UseParam):
		loc = query
		key = ac.ParamName
		ac.ParamName = ""
		ac.UseParam = false
	case ref.Value.In == cookie || (ref.Value.In == "" && ac.UseCookie):
		loc = cookie
		key = ac.CookieName
		ac.CookieName = ""
		ac.UseCookie = false
	}

	ref.Value.WithName(key).WithIn(loc).WithType(typeAPIKey)

	s.appendSecurity(ac.Name)
}

func (s *OAS) extractAPIKeySchemeTo(ac *apidef.AuthConfig, name string) {
	ref := s.Components.SecuritySchemes[name]
	ac.Name = name

	switch ref.Value.In {
	case header:
		ac.AuthHeaderName = ref.Value.Name
		ac.DisableHeader = false
	case query:
		ac.ParamName = ref.Value.Name
		ac.UseParam = true
	case cookie:
		ac.CookieName = ref.Value.Name
		ac.UseCookie = true
	}
}

func (s *OAS) fillOAuthScheme(accessTypes []osin.AccessRequestType, name string) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[name] = ref
	}

	flows := ref.Value.Flows
	if flows == nil {
		flows = &openapi3.OAuthFlows{}
	}

	for _, accessType := range accessTypes {
		switch accessType {
		case osin.AUTHORIZATION_CODE:
			if flows.AuthorizationCode == nil {
				flows.AuthorizationCode = &openapi3.OAuthFlow{}
			}

			setAuthorizationURLIfEmpty(flows.AuthorizationCode)
			setTokenURLIfEmpty(flows.AuthorizationCode)
			setScopesIfEmpty(flows.AuthorizationCode)
		case osin.CLIENT_CREDENTIALS:
			if flows.ClientCredentials == nil {
				flows.ClientCredentials = &openapi3.OAuthFlow{}
			}

			setTokenURLIfEmpty(flows.ClientCredentials)
			setScopesIfEmpty(flows.ClientCredentials)
		case osin.PASSWORD:
			if flows.Password == nil {
				flows.Password = &openapi3.OAuthFlow{}
			}

			setTokenURLIfEmpty(flows.Password)
			setScopesIfEmpty(flows.Password)
		case osin.IMPLICIT:
			if flows.Implicit == nil {
				flows.Implicit = &openapi3.OAuthFlow{}
			}

			setAuthorizationURLIfEmpty(flows.Implicit)
			setScopesIfEmpty(flows.Implicit)
		}
	}

	ref.Value.WithType(typeOAuth2).Flows = flows

	s.appendSecurity(name)
}

func (s *OAS) fillOAuthSchemeForExternal(name string) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[name] = ref
	}

	flows := ref.Value.Flows
	if flows == nil {
		flows = &openapi3.OAuthFlows{}
	}

	if flows.AuthorizationCode == nil {
		flows.AuthorizationCode = &openapi3.OAuthFlow{}
	}

	setAuthorizationURLIfEmpty(flows.AuthorizationCode)
	setTokenURLIfEmpty(flows.AuthorizationCode)
	setScopesIfEmpty(flows.AuthorizationCode)

	ref.Value.WithType(typeOAuth2).Flows = flows

	s.appendSecurity(name)
}

func (s *OAS) extractOAuthSchemeTo(api *apidef.APIDefinition, name string) {
	ref := s.Components.SecuritySchemes[name]

	flows := ref.Value.Flows
	if flows == nil {
		return
	}

	if flows.AuthorizationCode != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.AUTHORIZATION_CODE)
	}

	if flows.ClientCredentials != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
	}

	if flows.Password != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.PASSWORD)
	}

	if flows.Implicit != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.IMPLICIT)
	}
}

func (s *OAS) appendSecurity(name string) {
	if len(s.Security) == 0 {
		s.Security.With(openapi3.NewSecurityRequirement())
	}

	if _, found := s.Security[0][name]; !found {
		s.Security[0][name] = []string{}
	}
}

func setAuthorizationURLIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.AuthorizationURL == "" {
		flow.AuthorizationURL = "/oauth/authorize"
	}
}

func setTokenURLIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.TokenURL == "" {
		flow.TokenURL = "/oauth/token"
	}
}

func setScopesIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.Scopes == nil {
		flow.Scopes = make(map[string]string)
	}
}
