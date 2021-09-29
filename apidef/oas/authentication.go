package oas

import (
	"reflect"

	"github.com/TykTechnologies/tyk/apidef"
)

type Authentication struct {
	Enabled                bool   `bson:"enabled" json:"enabled"` // required
	StripAuthorizationData bool   `bson:"stripAuthorizationData,omitempty" json:"stripAuthorizationData,omitempty"`
	Token                  *Token `bson:"token,omitempty" json:"token,omitempty"`
	JWT                    *JWT   `bson:"jwt,omitempty" json:"jwt,omitempty"`
	Basic                  *Basic `bson:"basic,omitempty" json:"basic,omitempty"`
}

func (a *Authentication) Fill(api apidef.APIDefinition) {
	a.Enabled = !api.UseKeylessAccess
	a.StripAuthorizationData = api.StripAuthData

	if api.AuthConfigs == nil || len(api.AuthConfigs) == 0 {
		return
	}

	if authToken, ok := api.AuthConfigs["authToken"]; ok {
		if a.Token == nil {
			a.Token = &Token{}
		}

		a.Token.Fill(api.UseStandardAuth, authToken)
	}

	if reflect.DeepEqual(a.Token, &Token{}) {
		a.Token = nil
	}

	if _, ok := api.AuthConfigs["jwt"]; ok {
		if a.JWT == nil {
			a.JWT = &JWT{}
		}

		a.JWT.Fill(api)
	}

	if reflect.DeepEqual(a.JWT, &JWT{}) {
		a.JWT = nil
	}

	if _, ok := api.AuthConfigs["basic"]; ok {
		if a.Basic == nil {
			a.Basic = &Basic{}
		}

		a.Basic.Fill(api)
	}

	if reflect.DeepEqual(a.Basic, &Basic{}) {
		a.Basic = nil
	}
}

func (a *Authentication) ExtractTo(api *apidef.APIDefinition) {
	api.UseKeylessAccess = !a.Enabled
	api.StripAuthData = a.StripAuthorizationData

	if a.Token != nil {
		a.Token.ExtractTo(api)
	}

	if a.JWT != nil {
		a.JWT.ExtractTo(api)
	}

	if a.Basic != nil {
		a.Basic.ExtractTo(api)
	}
}

type Token struct {
	Enabled                 bool `bson:"enabled" json:"enabled"` // required
	AuthSources             `bson:",inline" json:",inline"`
	EnableClientCertificate bool       `bson:"enableClientCertificate,omitempty" json:"enableClientCertificate,omitempty"`
	Signature               *Signature `bson:"signatureValidation,omitempty" json:"signatureValidation,omitempty"`
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
	if (*t.Signature == Signature{}) {
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
	Header HeaderAuthSource `bson:"header" json:"header"` // required
	Cookie *AuthSource      `bson:"cookie,omitempty" json:"cookie,omitempty"`
	Param  *AuthSource      `bson:"param,omitempty" json:"param,omitempty"`
}

func (as *AuthSources) Fill(authConfig apidef.AuthConfig) {
	// Header
	as.Header = HeaderAuthSource{authConfig.AuthHeaderName}

	// Param
	if as.Param == nil {
		as.Param = &AuthSource{}
	}

	as.Param.Fill(authConfig.UseParam, authConfig.ParamName)
	if (*as.Param == AuthSource{}) {
		as.Param = nil
	}

	// Cookie
	if as.Cookie == nil {
		as.Cookie = &AuthSource{}
	}

	as.Cookie.Fill(authConfig.UseCookie, authConfig.CookieName)
	if (*as.Cookie == AuthSource{}) {
		as.Cookie = nil
	}
}

func (as *AuthSources) ExtractTo(authConfig *apidef.AuthConfig) {
	// Header
	authConfig.AuthHeaderName = as.Header.Name

	// Param
	if as.Param != nil {
		as.Param.ExtractTo(&authConfig.UseParam, &authConfig.ParamName)
	}

	// Cookie
	if as.Cookie != nil {
		as.Cookie.ExtractTo(&authConfig.UseCookie, &authConfig.CookieName)
	}
}

type HeaderAuthSource struct {
	Name string `bson:"name" json:"name"` // required
}

type AuthSource struct {
	Enabled bool   `bson:"enabled" json:"enabled"` // required
	Name    string `bson:"name,omitempty" json:"name,omitempty"`
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
	Enabled          bool   `bson:"enabled" json:"enabled"` // required
	Algorithm        string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	Header           string `bson:"header,omitempty" json:"header,omitempty"`
	Secret           string `bson:"secret,omitempty" json:"secret,omitempty"`
	AllowedClockSkew int64  `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
	ErrorCode        int    `bson:"errorCode,omitempty" json:"errorCode,omitempty"`
	ErrorMessage     string `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
}

func (s *Signature) Fill(authConfig apidef.AuthConfig) {
	signature := authConfig.Signature

	s.Enabled = authConfig.ValidateSignature
	s.Algorithm = signature.Algorithm
	s.Header = signature.Header
	s.Secret = signature.Secret
	s.AllowedClockSkew = signature.AllowedClockSkew
	s.ErrorCode = signature.ErrorCode
	s.ErrorMessage = signature.ErrorMessage
}

func (s *Signature) ExtractTo(authConfig *apidef.AuthConfig) {
	authConfig.ValidateSignature = s.Enabled

	authConfig.Signature.Algorithm = s.Algorithm
	authConfig.Signature.Header = s.Header
	authConfig.Signature.Secret = s.Secret
	authConfig.Signature.AllowedClockSkew = s.AllowedClockSkew
	authConfig.Signature.ErrorCode = s.ErrorCode
	authConfig.Signature.ErrorMessage = s.ErrorMessage
}

type JWT struct {
	Enabled                 bool `bson:"enabled" json:"enabled"` // required
	AuthSources             `bson:",inline" json:",inline"`
	Source                  string            `json:"source,omitempty"`
	SigningMethod           string            `bson:"signingMethod,omitempty" json:"signingMethod,omitempty"`
	IdentityBaseField       string            `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	SkipKid                 bool              `bson:"skipKid,omitempty" json:"skipKid,omitempty"`
	ScopeClaimName          string            `bson:"scopeClaimName,omitempty" json:"scopeClaimName,omitempty"`
	ScopeToPolicyMapping    map[string]string `bson:"scopeToPolicyMapping,omitempty" json:"scopeToPolicyMapping,omitempty"`
	PolicyFieldName         string            `bson:"policyFieldName,omitempty" json:"policyFieldName,omitempty"`
	ClientBaseField         string            `bson:"clientBaseField,omitempty" json:"clientBaseField,omitempty"`
	DefaultPolicies         []string          `bson:"defaultPolicies,omitempty" json:"defaultPolicies,omitempty"`
	IssuedAtValidationSkew  uint64            `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`
	NotBeforeValidationSkew uint64            `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`
	ExpiresAtValidationSkew uint64            `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`
}

func (j *JWT) Fill(api apidef.APIDefinition) {
	j.AuthSources.Fill(api.AuthConfigs["jwt"])

	j.Enabled = api.EnableJWT
	j.Source = api.JWTSource
	j.SigningMethod = api.JWTSigningMethod
	j.IdentityBaseField = api.JWTIdentityBaseField
	j.SkipKid = api.JWTSkipKid
	j.ScopeClaimName = api.JWTScopeClaimName
	j.ScopeToPolicyMapping = api.JWTScopeToPolicyMapping
	j.PolicyFieldName = api.JWTPolicyFieldName
	j.ClientBaseField = api.JWTClientIDBaseField
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
	api.JWTScopeClaimName = j.ScopeClaimName
	api.JWTScopeToPolicyMapping = j.ScopeToPolicyMapping
	api.JWTPolicyFieldName = j.PolicyFieldName
	api.JWTClientIDBaseField = j.ClientBaseField
	api.JWTDefaultPolicies = j.DefaultPolicies
	api.JWTIssuedAtValidationSkew = j.IssuedAtValidationSkew
	api.JWTNotBeforeValidationSkew = j.NotBeforeValidationSkew
	api.JWTExpiresAtValidationSkew = j.ExpiresAtValidationSkew
}

type Basic struct {
	Enabled                    bool `bson:"enabled" json:"enabled"` // required
	AuthSources                `bson:",inline" json:",inline"`
	DisableCaching             bool                        `bson:"disableCaching,omitempty" json:"disableCaching,omitempty"`
	CacheTTL                   int                         `bson:"cacheTTL,omitempty" json:"cacheTTL,omitempty"`
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

	if reflect.DeepEqual(b.ExtractCredentialsFromBody, &ExtractCredentialsFromBody{}) {
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
	Enabled        bool   `bson:"enabled" json:"enabled"` // required
	UserRegexp     string `bson:"userRegexp,omitempty" json:"userRegexp,omitempty"`
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
