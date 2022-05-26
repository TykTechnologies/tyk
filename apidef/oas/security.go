package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
)

const (
	typeApiKey      = "apiKey"
	typeHttp        = "http"
	typeOAuth2      = "oauth2"
	schemeBearer    = "bearer"
	schemeBasic     = "basic"
	bearerFormatJWT = "JWT"

	header = "header"
	query  = "query"
	cookie = "cookie"
)

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

func (s *OAS) fillToken(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillApiKeyScheme(&authConfig)

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

	s.extractApiKeySchemeTo(&authConfig, name)

	api.AuthConfigs[apidef.AuthTokenType] = authConfig
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

	ref.Value.WithType(typeHttp).WithScheme(schemeBearer).WithBearerFormat(bearerFormatJWT)

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

	ref.Value.WithType(typeHttp).WithScheme(schemeBasic)

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
			case v.Type == typeApiKey:
				s.extractTokenTo(api, schemeName)
			case v.Type == typeHttp && v.Scheme == schemeBearer && v.BearerFormat == bearerFormatJWT:
				s.extractJWTTo(api, schemeName)
			case v.Type == typeHttp && v.Scheme == schemeBasic:
				s.extractBasicTo(api, schemeName)
			case v.Type == typeOAuth2:
				s.extractOAuthTo(api, schemeName)
			}
		}
	}
}

func (s *OAS) fillApiKeyScheme(ac *apidef.AuthConfig) {
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

	ref.Value.WithName(key).WithIn(loc).WithType(typeApiKey)

	s.appendSecurity(ac.Name)
}

func (s *OAS) extractApiKeySchemeTo(ac *apidef.AuthConfig, name string) {
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
