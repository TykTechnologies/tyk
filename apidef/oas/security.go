package oas

import (
	"fmt"
	
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
	// Enabled activates the token based authentication mode.
	//
	// Tyk classic API definition: `auth_configs["authToken"].use_standard_auth`
	Enabled *bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains the configuration for authentication sources.
	AuthSources `bson:",inline" json:",inline"`

	// EnableClientCertificate allows to create dynamic keys based on certificates.
	//
	// Tyk classic API definition: `auth_configs["authToken"].use_certificate`
	EnableClientCertificate bool `bson:"enableClientCertificate,omitempty" json:"enableClientCertificate,omitempty"`

	// Signature holds the configuration for verifying the signature of the token.
	//
	// Tyk classic API definition: `auth_configs["authToken"].use_certificate`
	Signature *Signature `bson:"signatureValidation,omitempty" json:"signatureValidation,omitempty"`
}

// Import populates *Token from argument values.
func (t *Token) Import(nativeSS *openapi3.SecurityScheme, enable bool) {
	t.Enabled = &enable
	t.AuthSources.Import(nativeSS.In)
}

func (s *OAS) fillToken(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillAPIKeyScheme(&authConfig)

	token := &Token{}
	token.Enabled = &api.UseStandardAuth
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
	var enabled bool
	if token.Enabled != nil {
		enabled = *token.Enabled
	}
	api.UseStandardAuth = enabled
	authConfig.UseCertificate = token.EnableClientCertificate
	token.AuthSources.ExtractTo(&authConfig)
	if token.Signature != nil {
		token.Signature.ExtractTo(&authConfig)
	}

	s.extractAPIKeySchemeTo(&authConfig, name)

	api.AuthConfigs[apidef.AuthTokenType] = authConfig
}

// JWK represents a JSON Web Key containing configuration for JWKS endpoint and its cache timeout.
type JWK struct {
	// URL is the jwk endpoint.
	URL string `json:"url"`
	// CacheTimeout defines how long the JWKS is kept in the cache before forcing a refresh.
	CacheTimeout int64 `bson:"cacheTimeout" json:"cacheTimeout"`
}

// JWT holds the configuration for the JWT middleware.
type JWT struct {
	// Enabled activates the basic authentication mode.
	//
	// Tyk classic API definition: `enable_jwt`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources configures the source for the JWT.
	AuthSources `bson:",inline" json:",inline"`

	// Source contains the source for the JWT.
	//
	// Tyk classic API definition: `jwt_source`
	Source string `bson:"source,omitempty" json:"source,omitempty"`

	// JwksURIs contains a list of JSON Web Key Sets (JWKS) endpoints from which Tyk will retrieve JWKS to validate JSON Web Tokens (JWTs).
	JwksURIs []JWK `bson:"jwksURIs,omitempty" json:"jwksURIs,omitempty"`

	// SigningMethod contains the signing method to use for the JWT.
	//
	// Tyk classic API definition: `jwt_signing_method`
	SigningMethod string `bson:"signingMethod,omitempty" json:"signingMethod,omitempty"`

	// IdentityBaseField specifies the claim name uniquely identifying the subject of the JWT.
	// The identity fields that are checked in order are: `kid`, IdentityBaseField, `sub`.
	//
	// Tyk classic API definition: `jwt_identity_base_field`
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`

	// SubjectClaims specifies a list of claims that can be used to identity the subject of the JWT.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	SubjectClaims []string `bson:"subjectClaims,omitempty" json:"subjectClaims,omitempty"`

	// SkipKid controls skipping using the `kid` claim from a JWT (default behaviour).
	// When this is true, the field configured in IdentityBaseField is checked first.
	//
	// Tyk classic API definition: `jwt_skip_kid`
	SkipKid bool `bson:"skipKid,omitempty" json:"skipKid,omitempty"`

	// PolicyFieldName is a configurable claim name from which a policy ID is extracted.
	// The policy is applied to the session as a base policy.
	//
	// Tyk classic API definition: `jwt_policy_field_name`
	PolicyFieldName string `bson:"policyFieldName,omitempty" json:"policyFieldName,omitempty"`

	// BasePolicyClaims specifies a list of claims from which the base PolicyID is extracted.
	// The policy is applied to the session as a base policy.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	BasePolicyClaims []string `bson:"basePolicyClaims,omitempty" json:"basePolicyClaims,omitempty"`

	// ClientBaseField is used when PolicyFieldName is not provided. It will get
	// a session key and use the policies from that. The field ensures that requests
	// use the same session.
	//
	// Tyk classic API definition: `jwt_client_base_field`
	ClientBaseField string `bson:"clientBaseField,omitempty" json:"clientBaseField,omitempty"`

	// Scopes holds the scope to policy mappings for a claim name.
	Scopes *Scopes `bson:"scopes,omitempty" json:"scopes,omitempty"`

	// DefaultPolicies is a list of policy IDs that apply to the session.
	//
	// Tyk classic API definition: `jwt_default_policies`
	DefaultPolicies []string `bson:"defaultPolicies,omitempty" json:"defaultPolicies,omitempty"`

	// IssuedAtValidationSkew contains the duration in seconds for which token issuance can predate the current time during the request.
	//
	// Tyk classic API definition: `jwt_issued_at_validation_skew`.
	IssuedAtValidationSkew uint64 `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`

	// NotBeforeValidationSkew contains the duration in seconds for which token validity can predate the current time during the request.
	//
	// Tyk classic API definition: `jwt_not_before_validation_skew`.
	NotBeforeValidationSkew uint64 `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`

	// ExpiresAtValidationSkew contains the duration in seconds for which the token can be expired before we consider it expired.
	//
	// Tyk classic API definition: `jwt_expires_at_validation_skew`.
	ExpiresAtValidationSkew uint64 `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`

	// AllowedIssuers contains a list of accepted issuers for JWT validation.
	// When configured, the JWT's issuer claim must match one of these values.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	AllowedIssuers []string `bson:"allowedIssuers,omitempty" json:"allowedIssuers,omitempty"`

	// AllowedAudiences contains a list of accepted audiences for JWT validation.
	// When configured, the JWT's audience claim must match one of these values.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	AllowedAudiences []string `bson:"allowedAudiences,omitempty" json:"allowedAudiences,omitempty"`

	// JTIValidation contains the configuration for the validation of the JWT ID.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	JTIValidation JTIValidation `bson:"jtiValidation,omitempty" json:"jtiValidation,omitempty"`

	// AllowedSubjects contains a list of accepted subjects for JWT validation.
	// When configured, the subject from kid/identityBaseField/sub must match one of these values.
	// This field is a Tyk OAS only field and is only used in Tyk OAS APIs.
	AllowedSubjects []string `bson:"allowedSubjects,omitempty" json:"allowedSubjects,omitempty"`

	// IDPClientIDMappingDisabled prevents Tyk from automatically detecting the use of certain IDPs based on standard claims
	// that they include in the JWT: `client_id`, `cid`, `clientId`. Setting this flag to `true` disables the mapping and avoids
	// accidentally misidentifying the use of one of these IDPs if one of their standard values is configured in your JWT.
	//
	// Tyk classic API definition: `idp_client_id_mapping_disabled`.
	IDPClientIDMappingDisabled bool `bson:"idpClientIdMappingDisabled,omitempty" json:"idpClientIdMappingDisabled,omitempty"`

	// CustomClaimValidation contains custom validation rules for JWT claims.
	// It maps a claim name (including nested claims using dot notation) to its validation configuration.
	//
	// The validation can be one of three types:
	// - "required": claim must exist in the token (null/empty values are considered invalid)
	// - "exact_match": claim must exactly equal one of the specified values (case-sensitive)
	// - "contains": for strings, must contain one of the values as substring; for arrays, must contain one of the values as element
	//
	// Examples:
	// Basic validation: {"role": {"type": "exact_match", "allowedValues": ["admin", "user"]}}
	// Nested claim: {"user.metadata.level": {"type": "contains", "allowedValues": ["gold", "silver"]}}
	// Multiple rules: {"permissions": {"type": "contains", "allowedValues": ["read", "write"], "nonBlocking": true}}
	//
	// Claims can be of type string, number, boolean, or array. For arrays, the contains validation
	// checks if any of the array elements exactly match any of the allowed values.
	//
	// Tyk classic API definition: N/A (OAS only).
	CustomClaimValidation map[string]CustomClaimValidationConfig `bson:"customClaimValidation,omitempty" json:"customClaimValidation,omitempty"`
}

// CustomClaimValidationConfig defines the validation configuration for a custom JWT claim.
type CustomClaimValidationConfig struct {
	// Type specifies the type of validation to perform on the claim.
	// Supported types:
	// - required: validates that the claim exists and is non-null.
	// - exact_match: validates that the claim in the JWT equals one of the allowed values (case-sensitive).
	// - contains: validates that the claim in the JWT contains one of the allowed values.
	Type CustomClaimValidationType `bson:"type" json:"type"`

	// AllowedValues contains the values that Tyk will use to validate the claim for "exact_match" and "contains" validation types.
	// Not used for "required" validation type.
	// Supports string, number, boolean, and array values.
	// For arrays, validation succeeds if any array element matches any allowed value.
	AllowedValues []interface{} `bson:"allowedValues,omitempty" json:"allowedValues,omitempty"`

	// NonBlocking determines if validation failure should log a warning (true) or reject the request (false).
	// This enables gradual rollout of validation rules by monitoring before enforcing.
	// Multiple rules can be mixed, some blocking and others non-blocking.
	NonBlocking bool `bson:"nonBlocking,omitempty" json:"nonBlocking,omitempty"`
}

// CustomClaimValidationType represents how a JWT claim should be validated.
// This determines the validation logic used to check the claim value.
// The validation behavior varies based on both the type selected and the claim's data type.
type CustomClaimValidationType string

const (
	// ClaimValidationTypeRequired indicates that the claim must exist in the token and be non-null.
	// No value validation is performed - only existence is checked.
	ClaimValidationTypeRequired CustomClaimValidationType = "required"

	// ClaimValidationTypeExactMatch indicates that the claim must exactly equal one of the specified values.
	// The match is case-sensitive and type-aware (string/number/boolean/array).
	ClaimValidationTypeExactMatch CustomClaimValidationType = "exact_match"

	// ClaimValidationTypeContains indicates that the claim must contain one of the specified values.
	// For strings: checks if the claim contains any allowed value as a substring
	// For arrays: checks if the claim contains any allowed value as an element
	ClaimValidationTypeContains CustomClaimValidationType = "contains"
)

// JTIValidation contains the configuration for the validation of the JWT ID.
type JTIValidation struct {
	// Enabled indicates whether JWT ID claim is required.
	// When true, tokens must include a 'jti' claim.
	Enabled bool `bson:"enabled" json:"enabled"`
}

// Import populates *JWT based on arguments.
func (j *JWT) Import(enable bool) {
	j.Enabled = enable
	j.Header = &AuthSource{
		Enabled: true,
		Name:    defaultAuthSourceName,
	}
}

func (j *JWT) Normalize() {
	// copy the values of the new JWT validation
	if j == nil {
		return
	}
	if len(j.BasePolicyClaims) > 0 {
		j.PolicyFieldName = j.BasePolicyClaims[0]
	}
	if len(j.SubjectClaims) > 0 {
		j.IdentityBaseField = j.SubjectClaims[0]
	}
	if j.Scopes != nil && len(j.Scopes.Claims) > 0 {
		j.Scopes.ClaimName = j.Scopes.Claims[0]
	}
}

func (s *OAS) fillJWT(api apidef.APIDefinition) {
	ac, ok := api.AuthConfigs[apidef.JWTType]
	if !ok || ac.Name == "" {
		return
	}

	ss := s.T.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.T.Components.SecuritySchemes = ss
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

	var jwksURIs []JWK
	for _, jwksUri := range api.JWTJwksURIs {
		convertedJwksUri := JWK{
			URL:          jwksUri.URL,
			CacheTimeout: jwksUri.CacheTimeout,
		}
		jwksURIs = append(jwksURIs, convertedJwksUri)
	}
	jwt.JwksURIs = jwksURIs

	jwt.SigningMethod = api.JWTSigningMethod
	jwt.IdentityBaseField = api.JWTIdentityBaseField
	if jwt.IdentityBaseField != "" && len(jwt.SubjectClaims) == 0 {
		jwt.SubjectClaims = []string{jwt.IdentityBaseField}
	}
	jwt.SkipKid = api.JWTSkipKid
	jwt.PolicyFieldName = api.JWTPolicyFieldName
	if jwt.PolicyFieldName != "" && len(jwt.BasePolicyClaims) == 0 {
		jwt.BasePolicyClaims = []string{api.JWTPolicyFieldName}
	}
	jwt.ClientBaseField = api.JWTClientIDBaseField

	if jwt.Scopes == nil {
		jwt.Scopes = &Scopes{}
	}

	existing := s.GetJWTConfiguration()
	if existing != nil {
		jwt.BasePolicyClaims = existing.BasePolicyClaims
		jwt.SubjectClaims = existing.SubjectClaims
		jwt.AllowedIssuers = existing.AllowedIssuers
		jwt.AllowedAudiences = existing.AllowedAudiences
		jwt.AllowedSubjects = existing.AllowedSubjects
		jwt.JTIValidation.Enabled = existing.JTIValidation.Enabled

		if existing.Scopes != nil {
			jwt.Scopes.Claims = existing.Scopes.Claims
		}
		if existing.CustomClaimValidation != nil {
			jwt.CustomClaimValidation = existing.CustomClaimValidation
		}
	}

	jwt.Scopes.Fill(&api.Scopes.JWT)
	if ShouldOmit(jwt.Scopes) {
		jwt.Scopes = nil
	}

	jwt.DefaultPolicies = api.JWTDefaultPolicies
	jwt.IssuedAtValidationSkew = api.JWTIssuedAtValidationSkew
	jwt.NotBeforeValidationSkew = api.JWTNotBeforeValidationSkew
	jwt.ExpiresAtValidationSkew = api.JWTExpiresAtValidationSkew
	jwt.IDPClientIDMappingDisabled = api.IDPClientIDMappingDisabled

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

	var jwksURIs []apidef.JWK
	for _, jwksUri := range jwt.JwksURIs {
		convertedJwksUri := apidef.JWK{
			URL:          jwksUri.URL,
			CacheTimeout: jwksUri.CacheTimeout,
		}
		jwksURIs = append(jwksURIs, convertedJwksUri)
	}
	api.JWTJwksURIs = jwksURIs

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
	api.IDPClientIDMappingDisabled = jwt.IDPClientIDMappingDisabled

	api.AuthConfigs[apidef.JWTType] = ac
}

// Basic type holds configuration values related to http basic authentication.
type Basic struct {
	// Enabled activates the basic authentication mode.
	// Tyk classic API definition: `use_basic_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// AuthSources contains the source for HTTP Basic Auth credentials.
	AuthSources `bson:",inline" json:",inline"`
	// DisableCaching disables the caching of basic authentication key.
	// Tyk classic API definition: `basic_auth.disable_caching`
	DisableCaching bool `bson:"disableCaching,omitempty" json:"disableCaching,omitempty"`
	// CacheTTL is the TTL for a cached basic authentication key in seconds.
	// Tyk classic API definition: `basic_auth.cache_ttl`
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

	ss := s.T.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.T.Components.SecuritySchemes = ss
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
	// Enabled activates extracting credentials from body.
	// Tyk classic API definition: `basic_auth.extract_from_body`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// UserRegexp is the regex for username e.g. `<User>(.*)</User>`.
	// Tyk classic API definition: `basic_auth.userRegexp`
	UserRegexp string `bson:"userRegexp,omitempty" json:"userRegexp,omitempty"`
	// PasswordRegexp is the regex for password e.g. `<Password>(.*)</Password>`.
	// Tyk classic API definition: `basic_auth.passwordRegexp`
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
	// Enabled activates the OAuth middleware.
	//
	// Tyk classic API definition: `use_oauth2`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources configures the sources for OAuth credentials.
	AuthSources `bson:",inline" json:",inline"`

	// AllowedAuthorizeTypes is an array of OAuth authorization types.
	//
	// Tyk classic API definition: `oauth_meta.allowed_authorize_types`.
	AllowedAuthorizeTypes []osin.AuthorizeRequestType `bson:"allowedAuthorizeTypes,omitempty" json:"allowedAuthorizeTypes,omitempty"`

	// RefreshToken enables clients using a refresh token to get a new bearer access token.
	//
	// Tyk classic API definition: `oauth_meta.allowed_access_types` (contains REFRESH_TOKEN).
	RefreshToken bool `bson:"refreshToken,omitempty" json:"refreshToken,omitempty"`

	// AuthLoginRedirect configures a URL to redirect to after a successful login.
	//
	// Tyk classic API definition: `oauth_meta.auth_login_redirect`.
	AuthLoginRedirect string `bson:"authLoginRedirect,omitempty" json:"authLoginRedirect,omitempty"`

	// Notifications configures a URL trigger on key changes.
	//
	// Tyk classic API definition: `notifications`.
	Notifications *Notifications `bson:"notifications,omitempty" json:"notifications,omitempty"`
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

// OAuthProvider holds the configuration for validation and introspection of OAuth tokens.
type OAuthProvider struct {
	// JWT configures JWT validation.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt`.
	JWT *JWTValidation `bson:"jwt,omitempty" json:"jwt,omitempty"`
	// Introspection configures token introspection.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection`.
	Introspection *Introspection `bson:"introspection,omitempty" json:"introspection,omitempty"`
}

// JWTValidation holds configuration for validating access tokens by inspecing them
// against a third party API, usually one provided by the IDP.
type JWTValidation struct {
	// Enabled activates OAuth access token validation.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.enabled`.
	Enabled bool `bson:"enabled" json:"enabled"`

	// SigningMethod to verify signing method used in jwt - allowed values HMAC/RSA/ECDSA.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.signing_method`.
	SigningMethod string `bson:"signingMethod" json:"signingMethod"`

	// Source is the secret to verify signature. Valid values are:
	//
	// - a base64 encoded static secret,
	// - a valid JWK URL in plain text,
	// - a valid JWK URL in base64 encoded format.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.source`.
	Source string `bson:"source" json:"source"`

	// IdentityBaseField is the identity claim name.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.identity_base_field`.
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`

	// IssuedAtValidationSkew is the clock skew to be considered while validating the iat claim.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.issued_at_validation_skew`.
	IssuedAtValidationSkew uint64 `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`

	// NotBeforeValidationSkew is the clock skew to be considered while validating the nbf claim.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.not_before_validation_skew`.
	NotBeforeValidationSkew uint64 `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`

	// ExpiresAtValidationSkew is the clock skew to be considered while validating the exp claim.
	//
	// Tyk classic API definition: `external_oauth.providers[].jwt.expires_at_validation_skew`.
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

// Introspection holds configuration for OAuth token introspection.
type Introspection struct {
	// Enabled activates OAuth access token validation by introspection to a third party.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.enabled`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// URL is the URL of the third party provider's introspection endpoint.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.url`.
	URL string `bson:"url" json:"url"`
	// ClientID is the public identifier for the client, acquired from the third party.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.client_id`.
	ClientID string `bson:"clientId" json:"clientId"`
	// ClientSecret is a secret known only to the client and the authorisation server, acquired from the third party.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.client_secret`.
	ClientSecret string `bson:"clientSecret" json:"clientSecret"`
	// IdentityBaseField is the key showing where to find the user id in the claims. If it is empty, the `sub` key is looked at.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.identity_base_field`.
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	// Cache is the caching mechanism for introspection responses.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.cache`.
	Cache *IntrospectionCache `bson:"cache,omitempty" json:"cache,omitempty"`
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

// IntrospectionCache holds configuration for caching introspection requests.
type IntrospectionCache struct {
	// Enabled activates the caching mechanism for introspection responses.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.cache.enabled`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Timeout is the duration in seconds of how long the cached value stays.
	// For introspection caching, it is suggested to use a short interval.
	//
	// Tyk classic API definition: `external_oauth.providers[].introspection.cache.timeout`.
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

// ExternalOAuth holds configuration for an external OAuth provider.
// Deprecated: ExternalOAuth support was deprecated in Tyk 5.7.0.
// To avoid any disruptions, we recommend that you use JSON Web Token (JWT) instead,
// as explained in https://tyk.io/docs/basic-config-and-security/security/authentication-authorization/ext-oauth-middleware/.
type ExternalOAuth struct {
	// Enabled activates external oauth functionality.
	//
	// Tyk classic API definition: `external_oauth.enabled`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources configures the source for the authentication token.
	AuthSources `bson:",inline" json:",inline"`

	// Providers is used to configure OAuth providers.
	//
	// Tyk classic API definition: `external_oauth.providers`.
	Providers []OAuthProvider `bson:"providers" json:"providers"` // required
}

func (s *OAS) fillExternalOAuth(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.ExternalOAuthType]
	if !ok || authConfig.Name == "" {
		if !api.ExternalOAuth.Enabled {
			return
		}
		// Assign a sensible default to authConfig if api.ExternalOAuth.Enabled is true.
		authConfig = apidef.AuthConfig{
			Name:          apidef.ExternalOAuthType,
			DisableHeader: true,
		}
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
	//
	// Tyk classic API definition: `notifications.shared_secret`.
	SharedSecret string `bson:"sharedSecret,omitempty" json:"sharedSecret,omitempty"`
	// OnKeyChangeURL is the URL a request will be triggered against.
	//
	// Tyk classic API definition: `notifications.oauth_on_keychange_url`.
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

// isProprietaryAuth checks if an auth method is Tyk proprietary (not standard OpenAPI)
func isProprietaryAuth(authMethod string) bool {
	proprietary := []string{"hmac", "custom", "mtls", "coprocess"}
	for _, p := range proprietary {
		if authMethod == p {
			return true
		}
	}
	return false
}

func (s *OAS) fillSecurity(api apidef.APIDefinition) {
	fmt.Println("\n=== DEBUG fillSecurity START ===")
	fmt.Printf("API Name: %s\n", api.Name)
	fmt.Printf("SecurityProcessingMode: %s\n", api.SecurityProcessingMode)
	fmt.Printf("Input SecurityRequirements: %v\n", api.SecurityRequirements)
	
	tykAuthentication := s.GetTykExtension().Server.Authentication
	if tykAuthentication == nil {
		tykAuthentication = &Authentication{}
		s.GetTykExtension().Server.Authentication = tykAuthentication
	}

	if tykAuthentication.SecuritySchemes == nil {
		s.GetTykExtension().Server.Authentication.SecuritySchemes = make(SecuritySchemes)
	}

	tykAuthentication.Fill(api)

	if s.T.Components == nil {
		s.T.Components = &openapi3.Components{}
	}

	s.fillToken(api)
	s.fillJWT(api)
	s.fillBasic(api)
	s.fillOAuth(api)
	s.fillExternalOAuth(api)

	// Handle security requirements based on processing mode
	processingMode := api.SecurityProcessingMode
	if processingMode == "" {
		processingMode = "legacy"
	}

	if processingMode == "compliant" {
		// Compliant mode: separate OAS and vendor security
		oasSecurity := make(openapi3.SecurityRequirements, 0)
		vendorSecurity := [][]string{}

		if len(api.SecurityRequirements) > 0 {
			for _, requirement := range api.SecurityRequirements {
				isVendorOnly := true
				oasReq := openapi3.NewSecurityRequirement()
				vendorReq := []string{}
				
				for _, schemeName := range requirement {
					if isProprietaryAuth(schemeName) {
						vendorReq = append(vendorReq, schemeName)
					} else {
						oasReq[schemeName] = []string{}
						isVendorOnly = false
					}
				}
				
				if isVendorOnly && len(vendorReq) > 0 {
					vendorSecurity = append(vendorSecurity, vendorReq)
				} else if len(oasReq) > 0 {
					oasSecurity = append(oasSecurity, oasReq)
				}
			}
		} else if len(tykAuthentication.SecuritySchemes) > 0 {
			// No explicit requirements, create from schemes
			secReq := openapi3.NewSecurityRequirement()
			for name := range tykAuthentication.SecuritySchemes {
				if !isProprietaryAuth(name) {
					secReq[name] = []string{}
				}
			}
			if len(secReq) > 0 {
				oasSecurity = append(oasSecurity, secReq)
			}
		}

		s.T.Security = oasSecurity
		fmt.Println("COMPLIANT mode - OAS Security set to:")
		for i, req := range s.T.Security {
			fmt.Printf("  [%d]: %v\n", i, req)
		}
		if len(vendorSecurity) > 0 {
			tykAuthentication.Security = vendorSecurity
		}
	} else {
		// Legacy mode: keep traditional behavior
		if len(api.SecurityRequirements) > 0 {
			s.T.Security = make(openapi3.SecurityRequirements, 0, len(api.SecurityRequirements))
			for _, requirement := range api.SecurityRequirements {
				secReq := openapi3.NewSecurityRequirement()
				for _, schemeName := range requirement {
					// In legacy mode, don't separate vendor extensions
					secReq[schemeName] = []string{}
				}
				s.T.Security = append(s.T.Security, secReq)
			}
		} else if len(tykAuthentication.SecuritySchemes) > 0 {
			secReq := openapi3.NewSecurityRequirement()
			for name := range tykAuthentication.SecuritySchemes {
				secReq[name] = []string{}
			}
			if len(secReq) > 0 {
				s.T.Security = openapi3.SecurityRequirements{secReq}
				fmt.Println("LEGACY mode - Created MERGED requirement from schemes:")
				for i, req := range s.T.Security {
					fmt.Printf("  [%d]: %v\n", i, req)
				}
			}
		}
		fmt.Println("LEGACY mode - Final OAS Security:")
		for i, req := range s.T.Security {
			fmt.Printf("  [%d]: %v\n", i, req)
		}
	}
	fmt.Println("=== DEBUG fillSecurity END ===\n")

	if len(tykAuthentication.SecuritySchemes) == 0 {
		tykAuthentication.SecuritySchemes = nil
	}

	if ShouldOmit(tykAuthentication) {
		s.GetTykExtension().Server.Authentication = nil
	}
}

func (s *OAS) extractSecurityTo(api *apidef.APIDefinition) {
	fmt.Println("\n=== DEBUG extractSecurityTo START ===")
	fmt.Printf("API Name: %s\n", api.Name)
	fmt.Printf("OAS Security Requirements:\n")
	for i, req := range s.T.Security {
		fmt.Printf("  [%d]: %v\n", i, req)
	}
	
	if s.getTykAuthentication() == nil {
		s.GetTykExtension().Server.Authentication = &Authentication{}
		defer func() {
			s.GetTykExtension().Server.Authentication = nil
		}()
	}

	resetSecuritySchemes(api)

	s.getTykAuthentication().ExtractTo(api)

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	if len(s.T.Security) == 0 || s.T.Components == nil || len(s.T.Components.SecuritySchemes) == 0 {
		return
	}

	// Extract security requirements based on processing mode
	processingMode := api.SecurityProcessingMode
	if processingMode == "" {
		processingMode = "legacy"
	}

	// In compliant mode, extract all security requirements including vendor extension
	// In legacy mode, still extract but gateway will only use first
	if processingMode == "compliant" {
		// Concatenate OAS security with vendor extension security
		api.SecurityRequirements = make([][]string, 0)
		
		// Add OAS security requirements
		for _, requirement := range s.T.Security {
			schemes := make([]string, 0, len(requirement))
			for schemeName := range requirement {
				schemes = append(schemes, schemeName)
			}
			api.SecurityRequirements = append(api.SecurityRequirements, schemes)
		}
		
		// Add vendor extension security requirements
		if s.getTykAuthentication() != nil && len(s.getTykAuthentication().Security) > 0 {
			for _, vendorReq := range s.getTykAuthentication().Security {
				api.SecurityRequirements = append(api.SecurityRequirements, vendorReq)
			}
		}
	} else if len(s.T.Security) > 0 {
		// Legacy mode - extract all security requirements (even single ones)
		// This ensures they are preserved during the Fill/Extract cycle
		api.SecurityRequirements = make([][]string, 0, len(s.T.Security))
		for _, requirement := range s.T.Security {
			schemes := make([]string, 0, len(requirement))
			for schemeName := range requirement {
				schemes = append(schemes, schemeName)
			}
			api.SecurityRequirements = append(api.SecurityRequirements, schemes)
		}
		fmt.Printf("LEGACY mode - Extracted SecurityRequirements: %v\n", api.SecurityRequirements)
	}
	fmt.Println("=== DEBUG extractSecurityTo END ===\n")

	// Process first security requirement for backward compatibility
	for schemeName := range s.getTykSecuritySchemes() {
		if _, ok := s.T.Security[0][schemeName]; ok {
			v := s.T.Components.SecuritySchemes[schemeName].Value
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

func (s *OAS) GetJWTConfiguration() *JWT {
	if len(s.T.Security) == 0 {
		return nil
	}

	for keyName := range s.getTykSecuritySchemes() {
		if _, ok := s.T.Security[0][keyName]; ok {
			v := s.T.Components.SecuritySchemes[keyName].Value
			if v.Type == typeHTTP && v.Scheme == schemeBearer && v.BearerFormat == bearerFormatJWT {
				return s.getTykJWTAuth(keyName)
			}
		}
	}
	return nil
}

func resetSecuritySchemes(api *apidef.APIDefinition) {
	api.AuthConfigs = nil

	// OAuth2
	api.UseOauth2 = false
	api.Oauth2Meta.AllowedAccessTypes = nil
	api.Oauth2Meta.AllowedAuthorizeTypes = nil
	api.Oauth2Meta.AuthorizeLoginRedirect = ""
	api.NotificationsDetails = apidef.NotificationsManager{}

	// External OAuth
	api.ExternalOAuth = apidef.ExternalOAuth{}

	// OIDC holds configuration for OpenID Connect.
	// Deprecated: OIDC support has been deprecated from 5.7.0.
	// To avoid any disruptions, we recommend that you use JSON Web Token (JWT) instead,
	// as explained in https://tyk.io/docs/api-management/client-authentication/#integrate-with-openid-connect-deprecated.
	api.UseOpenID = false
	api.Scopes.OIDC = apidef.ScopeClaim{}
	api.OpenIDOptions = apidef.OpenIDOptions{}

	// Basic
	api.UseBasicAuth = false
	api.BasicAuth.DisableCaching = false
	api.BasicAuth.CacheTTL = 0
	api.BasicAuth.ExtractFromBody = false
	api.BasicAuth.BodyUserRegexp = ""
	api.BasicAuth.BodyPasswordRegexp = ""
	delete(api.AuthConfigs, "basic")

	// HMAC
	api.EnableSignatureChecking = false
	api.HmacAllowedClockSkew = 0
	api.HmacAllowedAlgorithms = nil

	// JWT
	api.EnableJWT = false
	api.JWTSource = ""
	api.JWTJwksURIs = nil
	api.JWTSigningMethod = ""
	api.JWTIdentityBaseField = ""
	api.JWTSkipKid = false
	api.JWTPolicyFieldName = ""
	api.JWTClientIDBaseField = ""
	api.Scopes.JWT = apidef.ScopeClaim{}
	api.JWTDefaultPolicies = nil
	api.JWTIssuedAtValidationSkew = 0
	api.JWTExpiresAtValidationSkew = 0
	api.JWTNotBeforeValidationSkew = 0

	// Auth Token
	api.UseStandardAuth = false

	// Custom
	api.CustomPluginAuthEnabled = false
	api.CustomMiddleware.AuthCheck = apidef.MiddlewareDefinition{Disabled: true}
	api.CustomMiddleware.IdExtractor = apidef.MiddlewareIdExtractor{Disabled: true}
}

func (s *OAS) fillAPIKeyScheme(ac *apidef.AuthConfig) {
	ss := s.T.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.T.Components.SecuritySchemes = ss
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
	ref := s.T.Components.SecuritySchemes[name]
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
	ss := s.T.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.T.Components.SecuritySchemes = ss
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
	ss := s.T.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.T.Components.SecuritySchemes = ss
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
	ref := s.T.Components.SecuritySchemes[name]

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
	if len(s.T.Security) == 0 {
		s.T.Security.With(openapi3.NewSecurityRequirement())
	}

	if _, found := s.T.Security[0][name]; !found {
		s.T.Security[0][name] = []string{}
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
