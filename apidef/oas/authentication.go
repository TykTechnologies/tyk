package oas

import (
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"

	"github.com/TykTechnologies/tyk/apidef"
	clone "github.com/huandu/go-clone/generic"
)

// SecurityProcessingMode constants define how multiple security requirements are processed
const (
	// SecurityProcessingModeLegacy processes only the first security requirement and uses BaseIdentityProvider
	SecurityProcessingModeLegacy = "legacy"

	// SecurityProcessingModeCompliant processes all security requirements with OR logic and uses dynamic identity provider
	SecurityProcessingModeCompliant = "compliant"
)

// ValidateSecurityProcessingMode validates the security processing mode value.
func ValidateSecurityProcessingMode(mode string) bool {
	return mode == "" || mode == SecurityProcessingModeLegacy || mode == SecurityProcessingModeCompliant
}

// GetDefaultSecurityProcessingMode returns the default security processing mode.
func GetDefaultSecurityProcessingMode() string {
	return SecurityProcessingModeLegacy
}

// Authentication contains configuration about the authentication methods and security policies applied to requests.
type Authentication struct {
	// Enabled makes the API protected when one of the authentication modes is enabled.
	//
	// Tyk classic API definition: `!use_keyless`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not passed to the upstream.
	//
	// Tyk classic API definition: `strip_auth_data`.
	StripAuthorizationData bool `bson:"stripAuthorizationData,omitempty" json:"stripAuthorizationData,omitempty"`

	// BaseIdentityProvider enables the use of multiple authentication mechanisms.
	// It provides the session object that determines access control, rate limits and usage quotas.
	//
	// It should be set to one of the following:
	//
	// - `auth_token`
	// - `hmac_key`
	// - `basic_auth_user`
	// - `jwt_claim`
	// - `oidc_user`
	// - `oauth_key`
	// - `custom_auth`
	//
	// Tyk classic API definition: `base_identity_provided_by`.
	BaseIdentityProvider apidef.AuthTypeEnum `bson:"baseIdentityProvider,omitempty" json:"baseIdentityProvider,omitempty"`

	// HMAC contains the configurations related to HMAC authentication mode.
	//
	// Tyk classic API definition: `auth_configs["hmac"]`
	HMAC *HMAC `bson:"hmac,omitempty" json:"hmac,omitempty"`

	// OIDC contains the configurations related to OIDC authentication mode.
	//
	// Tyk classic API definition: `auth_configs["oidc"]`
	OIDC *OIDC `bson:"oidc,omitempty" json:"oidc,omitempty"`

	// Custom contains the configurations related to Custom authentication mode.
	//
	// Tyk classic API definition: `auth_configs["coprocess"]`
	Custom *CustomPluginAuthentication `bson:"custom,omitempty" json:"custom,omitempty"`

	// SecuritySchemes contains security schemes definitions.
	SecuritySchemes *SecuritySchemes `bson:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`

	// CustomKeyLifetime contains configuration for the maximum retention period for access tokens.
	CustomKeyLifetime *CustomKeyLifetime `bson:"customKeyLifetime,omitempty" json:"customKeyLifetime,omitempty"`

	// SecurityProcessingMode controls how Tyk will process the OpenAPI `security` field if multiple security requirement objects are declared.
	// - "legacy" (default): Only the first security requirement object will be processed; uses BaseIdentityProvider to create the session object.
	// - "compliant": All security requirement objects will be processed, request will be authorized if any of these are validated; the origin for the session object will be determined dynamically based on the validated security requirement.
	SecurityProcessingMode string `bson:"securityProcessingMode,omitempty" json:"securityProcessingMode,omitempty"`

	// Security is an extension to the OpenAPI security field and is used when securityProcessingMode is set to "compliant".
	// This can be used to combine any declared securitySchemes including Tyk proprietary auth methods.
	Security [][]string `bson:"security,omitempty" json:"security,omitempty"`
}

// CustomKeyLifetime contains configuration for custom key retention.
type CustomKeyLifetime struct {
	// Enabled enables custom maximum retention for keys for the API.
	Enabled bool `bson:"enabled,omitempty" json:"enabled,omitempty"`
	// Value configures the expiry interval for a Key.
	// The value is a string that specifies the interval in a compact form,
	// where hours, minutes and seconds are denoted by 'h', 'm' and 's' respectively.
	// Multiple units can be combined to represent the duration.
	//
	// Examples of valid shorthand notations:
	// - "1h"   : one hour
	// - "20m"  : twenty minutes
	// - "30s"  : thirty seconds
	// - "1m29s": one minute and twenty-nine seconds
	// - "1h30m" : one hour and thirty minutes
	//
	// An empty value is interpreted as "0s"
	//
	// Tyk classic API definition: `session_lifetime`.
	Value ReadableDuration `bson:"value" json:"value"`
	// RespectValidity ensures that Tyk respects the expiry configured in the key when the API level configuration grants a shorter lifetime.
	// That is, Redis waits until the key has expired before deleting it.
	//
	// Tyk classic API definition: `session_lifetime_respects_key_expiration`.
	RespectValidity bool `bson:"respectValidity,omitempty" json:"respectValidity,omitempty"`
}

// Fill fills *CustomKeyLifetime from apidef.APIDefinition.
func (k *CustomKeyLifetime) Fill(api apidef.APIDefinition) {
	k.RespectValidity = api.SessionLifetimeRespectsKeyExpiration

	if api.SessionLifetime == 0 {
		k.Enabled = false
	} else {
		k.Enabled = true
		k.Value = ReadableDuration(time.Duration(api.SessionLifetime) * time.Second)
	}
}

// ExtractTo extracts *Authentication into *apidef.APIDefinition.
func (k *CustomKeyLifetime) ExtractTo(api *apidef.APIDefinition) {
	api.SessionLifetimeRespectsKeyExpiration = k.RespectValidity

	if k.Enabled {
		api.SessionLifetime = int64(k.Value.Seconds())
	} else {
		api.SessionLifetime = 0
	}
}

// Fill fills *Authentication from apidef.APIDefinition.
func (a *Authentication) Fill(api apidef.APIDefinition) {
	a.Enabled = !api.UseKeylessAccess
	a.StripAuthorizationData = api.StripAuthData
	a.BaseIdentityProvider = api.BaseIdentityProvidedBy

	if a.Custom == nil {
		a.Custom = &CustomPluginAuthentication{}
	}

	a.Custom.Fill(api)

	if ShouldOmit(a.Custom) {
		a.Custom = nil
	}

	if a.CustomKeyLifetime == nil {
		a.CustomKeyLifetime = &CustomKeyLifetime{}
	}

	a.CustomKeyLifetime.Fill(api)

	if ShouldOmit(a.CustomKeyLifetime) {
		a.CustomKeyLifetime = nil
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

	if a.Custom == nil {
		a.Custom = &CustomPluginAuthentication{}
		defer func() {
			a.Custom = nil
		}()
	}

	a.Custom.ExtractTo(api)

	if a.CustomKeyLifetime == nil {
		a.CustomKeyLifetime = &CustomKeyLifetime{}
		defer func() {
			a.CustomKeyLifetime = nil
		}()
	}

	a.CustomKeyLifetime.ExtractTo(api)
}

// SecuritySchemes zero value is usable. Methods lazily initialize internal state.
// Recommendation: prefer NewSecuritySchemes for clarity and explicit initialization.
type SecuritySchemes struct {
	container map[string]interface{}
	mutex     sync.RWMutex
}

// NewSecuritySchemes constructs a new, empty `SecuritySchemes` value with an initialized container map.
// The returned pointer is safe for concurrent use via the provided methods.
func NewSecuritySchemes() *SecuritySchemes {
	return &SecuritySchemes{container: make(map[string]interface{})}
}

// isStructPointer reports whether the provided value is a non-nil pointer to a struct.
// We use this to detect write targets that can absorb map-backed schemes so that we can
// promote stored maps to concrete structs without allocating new containers.
func isStructPointer(value interface{}) bool {
	if value == nil {
		return false
	}

	val := reflect.ValueOf(value)
	return val.Kind() == reflect.Ptr && !val.IsNil() && val.Elem().Kind() == reflect.Struct
}

// Set stores a security scheme by name.
// Normalizing any existing map-backed data here ensures every caller subsequently observes a typed
// value instead of JSON-shaped maps, keeping conversions centralized and thread-safe.
func (ss *SecuritySchemes) Set(key string, value interface{}) {
	if ss == nil {
		return
	}
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	if ss.container == nil {
		ss.container = make(map[string]interface{})
	}

	existing, exists := ss.container[key]
	if exists && isStructPointer(value) {
		if isStructPointer(existing) && reflect.TypeOf(existing) == reflect.TypeOf(value) {
			return
		}
		if m, isMap := existing.(map[string]interface{}); isMap {
			if !toStructIfMap(m, value) {
				log.Warnf("Failed to convert map-based scheme %q into %T; overwriting malformed data", key, value)
			}
		}
	}

	ss.container[key] = value
}

// Get retrieves a security scheme by name.
// It returns the stored value and true when present, otherwise (nil, false).
func (ss *SecuritySchemes) Get(key string) (interface{}, bool) {
	if ss == nil {
		return nil, false
	}
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	if ss.container == nil {
		return nil, false
	}
	value, ok := ss.container[key]
	return value, ok
}

// Delete removes a scheme from the receiver by name.
// It silently returns when the receiver or its container map is nil.
func (ss *SecuritySchemes) Delete(key string) {
	if ss == nil {
		return
	}
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	if ss.container == nil {
		return
	}
	delete(ss.container, key)
}

// Len reports the number of registered security schemes.
// A nil receiver reports zero.
func (ss *SecuritySchemes) Len() int {
	if ss == nil {
		return 0
	}
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	return len(ss.container)
}

// Iter returns a snapshot under a short read lock to avoid holding locks during iteration.
// This allocates per call. Given the typical small number of schemes, the trade-off is acceptable.
func (ss *SecuritySchemes) Iter() iter.Seq2[string, interface{}] {
	return func(yield func(string, interface{}) bool) {
		if ss == nil {
			return
		}

		ss.mutex.RLock()
		if ss.container == nil {
			ss.mutex.RUnlock()
			return
		}

		snap := make([]struct {
			k string
			v interface{}
		}, 0, len(ss.container))
		for k, v := range ss.container {
			snap = append(snap, struct {
				k string
				v interface{}
			}{k, v})
		}
		ss.mutex.RUnlock()

		for _, e := range snap {
			if !yield(e.k, e.v) {
				return
			}
		}
	}
}

// MarshalJSON implements json.Marshaler.
// It snapshots the map under RLock, unlocks, then marshals.
func (ss *SecuritySchemes) MarshalJSON() ([]byte, error) {
	if ss == nil {
		return []byte(`{}`), nil
	}

	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	if ss.container == nil {
		return []byte(`{}`), nil
	}

	return json.Marshal(ss.container)
}

// UnmarshalJSON implements json.Unmarshaler.
// It builds a temporary map, then replaces the internal map under Lock.
func (ss *SecuritySchemes) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		ss.mutex.Lock()
		ss.container = make(map[string]interface{})
		ss.mutex.Unlock()
		return nil
	}

	tmp := make(map[string]interface{})
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	ss.mutex.Lock()
	ss.container = tmp
	ss.mutex.Unlock()
	return nil
}

// MarshalYAML makes SecuritySchemes YAML-friendly by exposing its container map.
func (ss *SecuritySchemes) MarshalYAML() (interface{}, error) {
	if ss == nil {
		return map[string]interface{}{}, nil
	}
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	if ss.container == nil {
		return map[string]interface{}{}, nil
	}
	return clone.Clone(ss.container), nil
}

// UnmarshalYAML populates SecuritySchemes.container from YAML.
func (ss *SecuritySchemes) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag == "!!null" {
		ss.mutex.Lock()
		ss.container = make(map[string]interface{})
		ss.mutex.Unlock()
		return nil
	}

	var tmp map[string]interface{}
	if err := n.Decode(&tmp); err != nil {
		return err
	}

	ss.mutex.Lock()
	ss.container = tmp
	ss.mutex.Unlock()
	return nil
}

// SecurityScheme defines an Importer interface for security schemes.
type SecurityScheme interface {
	Import(nativeSS *openapi3.SecurityScheme, enable bool)
}

// loadForImport returns an existing *T if present,
// or builds a new *T hydrated from a map (if possible),
// or otherwise returns a zero-value *T.
func loadForImport[T any](ss *SecuritySchemes, name string) *T {
	if ss == nil {
		return nil
	}

	scheme, exists := ss.Get(name)
	if !exists {
		return new(T)
	}

	if typed, ok := scheme.(*T); ok {
		return typed
	}

	v := new(T)
	toStructIfMap(scheme, v)
	return v
}

func (ss *SecuritySchemes) Import(name string, nativeSS *openapi3.SecurityScheme, enable bool) error {
	if ss == nil {
		return fmt.Errorf("SecuritySchemes is nil")
	}

	switch {
	case nativeSS.Type == typeAPIKey:
		token := loadForImport[Token](ss, name)
		token.Enabled = &enable
		ss.Set(name, token)

	case nativeSS.Type == typeHTTP &&
		nativeSS.Scheme == schemeBearer &&
		nativeSS.BearerFormat == bearerFormatJWT:

		jwt := loadForImport[JWT](ss, name)
		jwt.Import(enable)
		ss.Set(name, jwt)

	case nativeSS.Type == typeHTTP &&
		nativeSS.Scheme == schemeBasic:

		basic := loadForImport[Basic](ss, name)
		basic.Import(enable)
		ss.Set(name, basic)

	case nativeSS.Type == typeOAuth2:
		oauth := loadForImport[OAuth](ss, name)
		oauth.Import(enable)
		ss.Set(name, oauth)

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
func (ss *SecuritySchemes) GetBaseIdentityProvider() (res apidef.AuthTypeEnum) {
	if ss == nil || ss.Len() < 2 {
		return
	}

	resBaseIdentityProvider := baseIdentityProviderPrecedence(apidef.AuthTypeNone)
	res = apidef.OAuthKey

	for _, scheme := range ss.Iter() {
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
// Tyk classic API definition: `auth_configs{}`.
type AuthSources struct {
	// Header contains configurations for the header value auth source, it is enabled by default.
	//
	// Tyk classic API definition: `auth_configs[x].header`
	Header *AuthSource `bson:"header,omitempty" json:"header,omitempty"`

	// Cookie contains configurations for the cookie value auth source.
	//
	// Tyk classic API definition: `auth_configs[x].cookie`
	Cookie *AuthSource `bson:"cookie,omitempty" json:"cookie,omitempty"`

	// Query contains configurations for the query parameters auth source.
	//
	// Tyk classic API definition: `auth_configs[x].query`
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
	// Enabled activates the auth source.
	//
	// Tyk classic API definition: `auth_configs[X].use_param/use_cookie`.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name is the name of the auth source.
	//
	// Tyk classic API definition: `auth_configs[X].param_name/cookie_name`.
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
	// Enabled activates signature validation.
	//
	// Tyk classic API definition: `auth_configs[X].validate_signature`.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Algorithm is the signature method to use.
	//
	// Tyk classic API definition: `auth_configs[X].signature.algorithm`.
	Algorithm string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	// Header is the name of the header to consume.
	//
	// Tyk classic API definition: `auth_configs[X].signature.header`.
	Header string `bson:"header,omitempty" json:"header,omitempty"`
	// Query is the name of the query parameter to consume.
	//
	// Tyk classic API definition: `auth_configs[X].signature.use_param/param_name`.
	Query AuthSource `bson:"query,omitempty" json:"query,omitempty"`
	// Secret is the signing secret used for signature validation.
	//
	// Tyk classic API definition: `auth_configs[X].signature.secret`.
	Secret string `bson:"secret,omitempty" json:"secret,omitempty"`
	// AllowedClockSkew configures a grace period in seconds during which an expired token is still valid.
	//
	// Tyk classic API definition: `auth_configs[X].signature.allowed_clock_skew`.
	AllowedClockSkew int64 `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
	// ErrorCode configures the HTTP response code for a validation failure.
	// If unconfigured, a HTTP 401 Unauthorized status code will be emitted.
	//
	// Tyk classic API definition: `auth_configs[X].signature.error_code`.
	ErrorCode int `bson:"errorCode,omitempty" json:"errorCode,omitempty"`
	// ErrorMessage configures the error message that is emitted on validation failure.
	// A default error message is emitted if unset.
	//
	// Tyk classic API definition: `auth_configs[X].signature.error_message`.
	ErrorMessage string `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
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
// This struct is used for both JWT and OIDC authentication.
type Scopes struct {
	// ClaimName contains the claim name.
	//
	// Tyk classic API definition:
	// - For OIDC: `scopes.oidc.scope_claim_name`
	// - For JWT: `scopes.jwt.scope_claim_name`
	ClaimName string `bson:"claimName,omitempty" json:"claimName,omitempty"`

	// Claims specifies a list of claims that can be used to provide the scope-to-policy mapping.
	// The first match from the list found in the token will be interrogated to retrieve the scopes that are then checked against the scopeToPolicyMapping.
	Claims []string `bson:"claims,omitempty" json:"claims,omitempty"`

	// ScopeToPolicyMapping contains the mappings of scopes to policy IDs.
	//
	// Tyk classic API definition:
	// - For OIDC: `scopes.oidc.scope_to_policy`
	// - For JWT: `scopes.jwt.scope_to_policy`
	ScopeToPolicyMapping []ScopeToPolicy `bson:"scopeToPolicyMapping,omitempty" json:"scopeToPolicyMapping,omitempty"`
}

// Fill fills *Scopes from *apidef.ScopeClaim.
func (s *Scopes) Fill(scopeClaim *apidef.ScopeClaim) {
	s.ClaimName = scopeClaim.ScopeClaimName
	if s.ClaimName != "" && len(s.Claims) < 1 {
		s.Claims = []string{scopeClaim.ScopeClaimName}
	}

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

	scopeClaim.ScopeToPolicy = map[string]string{}
	for _, v := range s.ScopeToPolicyMapping {
		scopeClaim.ScopeToPolicy[v.Scope] = v.PolicyID
	}
}

// ScopeToPolicy contains a single scope to policy ID mapping.
// This struct is used for both JWT and OIDC authentication.
type ScopeToPolicy struct {
	// Scope contains the scope name.
	//
	// Tyk classic API definition:
	// - For OIDC: Key in `scopes.oidc.scope_to_policy` map
	// - For JWT: Key in `scopes.jwt.scope_to_policy` map.
	Scope string `bson:"scope,omitempty" json:"scope,omitempty"`

	// PolicyID contains the Policy ID.
	//
	// Tyk classic API definition:
	// - For OIDC: Value in `scopes.oidc.scope_to_policy` map
	// - For JWT: Value in `scopes.jwt.scope_to_policy` map.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

// HMAC holds the configuration for the HMAC authentication mode.
type HMAC struct {
	// Enabled activates the HMAC authentication mode.
	//
	// Tyk classic API definition: `enable_signature_checking`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains authentication token source configuration (header, cookie, query).
	AuthSources `bson:",inline" json:",inline"`

	// AllowedAlgorithms is the array of HMAC algorithms which are allowed.
	//
	// Tyk supports the following HMAC algorithms:
	//
	// - `hmac-sha1`
	// - `hmac-sha256`
	// - `hmac-sha384`
	// - `hmac-sha512`
	//
	// and reads the value from the algorithm header.
	//
	// Tyk classic API definition: `hmac_allowed_algorithms`.
	AllowedAlgorithms []string `bson:"allowedAlgorithms,omitempty" json:"allowedAlgorithms,omitempty"`

	// AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
	// The default value is `0`, which deactivates clock skew checks.
	//
	// Tyk classic API definition: `hmac_allowed_clock_skew`.
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
// OIDC support will be deprecated starting from 5.7.0.
// To avoid any disruptions, we recommend that you use JSON Web Token (JWT) instead,
// as explained in https://tyk.io/docs/basic-config-and-security/security/authentication-authorization/openid-connect/.
type OIDC struct {
	// Enabled activates the OIDC authentication mode.
	//
	// Tyk classic API definition: `use_openid`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources contains authentication token source configuration (header, cookie, query).
	AuthSources `bson:",inline" json:",inline"`

	// SegregateByClientId is a boolean flag. If set to `true, the policies will be applied to a combination of Client ID and User ID.
	//
	// Tyk classic API definition: `openid_options.segregate_by_client`.
	SegregateByClientId bool `bson:"segregateByClientId,omitempty" json:"segregateByClientId,omitempty"`

	// Providers contains a list of authorized providers, their Client IDs and matched policies.
	//
	// Tyk classic API definition: `openid_options.providers`.
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

	api.OpenIDOptions.Providers = []apidef.OIDProviderConfig{}
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
	//
	// Tyk classic API definition: `openid_options.providers[].issuer`.
	Issuer string `bson:"issuer,omitempty" json:"issuer,omitempty"`

	// ClientToPolicyMapping contains mappings of Client IDs to Policy IDs.
	//
	// Tyk classic API definition: `openid_options.providers[].client_ids`.
	ClientToPolicyMapping []ClientToPolicy `bson:"clientToPolicyMapping,omitempty" json:"clientToPolicyMapping,omitempty"`
}

// ClientToPolicy contains a 1-1 mapping between Client ID and Policy ID.
type ClientToPolicy struct {
	// ClientID contains a Client ID.
	//
	// Tyk classic API definition: Key in `openid_options.providers[].client_ids` map.
	ClientID string `bson:"clientId,omitempty" json:"clientId,omitempty"`

	// PolicyID contains a Policy ID.
	//
	// Tyk classic API definition: Value in `openid_options.providers[].client_ids` map.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}

// CustomPluginAuthentication holds configuration for custom plugins.
type CustomPluginAuthentication struct {
	// Enabled activates the CustomPluginAuthentication authentication mode.
	//
	// Tyk classic API definition: `enable_coprocess_auth`/`use_go_plugin_auth`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Config contains configuration related to custom authentication plugin.
	//
	// Tyk classic API definition: `custom_middleware.auth_check`.
	Config *AuthenticationPlugin `bson:"config,omitempty" json:"config,omitempty"`

	// AuthSources contains authentication token sources (header, cookie, query).
	// Valid only when driver is coprocess.
	//
	// Tyk classic API definition: `auth_configs["coprocess"]`.
	AuthSources `bson:",inline" json:",inline"`
}

// Fill fills *CustomPluginAuthentication from apidef.AuthConfig.
func (c *CustomPluginAuthentication) Fill(api apidef.APIDefinition) {
	c.Enabled = api.CustomPluginAuthEnabled

	if c.Config == nil {
		c.Config = &AuthenticationPlugin{}
	}

	c.Config.Fill(api)
	if ShouldOmit(c.Config) {
		c.Config = nil
	}

	if ShouldOmit(api.AuthConfigs[apidef.CoprocessType]) {
		return
	}

	c.AuthSources.Fill(api.AuthConfigs[apidef.CoprocessType])
}

// ExtractTo extracts *CustomPluginAuthentication to *apidef.APIDefinition.
func (c *CustomPluginAuthentication) ExtractTo(api *apidef.APIDefinition) {
	api.CustomPluginAuthEnabled = c.Enabled

	if c.Config == nil {
		c.Config = &AuthenticationPlugin{}
		defer func() {
			c.Config = nil
		}()
	}

	c.Config.ExtractTo(api)

	authConfig := apidef.AuthConfig{}
	c.AuthSources.ExtractTo(&authConfig)

	if reflect.DeepEqual(authConfig, apidef.AuthConfig{DisableHeader: true}) {
		return
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	api.AuthConfigs[apidef.CoprocessType] = authConfig
}

// AuthenticationPlugin holds the configuration for custom authentication plugin.
type AuthenticationPlugin struct {
	// Enabled activates custom authentication plugin.
	//
	// Tyk classic API definition: `custom_middleware.auth_check.disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// FunctionName is the name of authentication method.
	//
	// Tyk classic API definition: `custom_middleware.auth_check.name`.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to shared object file in case of goplugin mode or path to JS code in case of otto auth plugin.
	//
	// Tyk classic API definition: `custom_middleware.auth_check.path`.
	Path string `bson:"path" json:"path"`
	// RawBodyOnly if set to true, do not fill body in request or response object.
	//
	// Tyk classic API definition: `custom_middleware.auth_check.raw_body_only`.
	RawBodyOnly bool `bson:"rawBodyOnly,omitempty" json:"rawBodyOnly,omitempty"`
	// RequireSession passes down the session information for plugins after authentication.
	//
	// Tyk classic API definition: `custom_middleware.auth_check.require_session`.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
	// IDExtractor configures ID extractor with coprocess custom authentication.
	//
	// Tyk classic API definition: `custom_middleware.id_extractor`.
	IDExtractor *IDExtractor `bson:"idExtractor,omitempty" json:"idExtractor,omitempty"`
}

func (ap *AuthenticationPlugin) Fill(api apidef.APIDefinition) {
	ap.FunctionName = api.CustomMiddleware.AuthCheck.Name
	ap.Path = api.CustomMiddleware.AuthCheck.Path
	ap.RawBodyOnly = api.CustomMiddleware.AuthCheck.RawBodyOnly
	ap.RequireSession = api.CustomMiddleware.AuthCheck.RequireSession
	ap.Enabled = !api.CustomMiddleware.AuthCheck.Disabled
	if ap.IDExtractor == nil {
		ap.IDExtractor = &IDExtractor{}
	}

	ap.IDExtractor.Fill(api)
	if ShouldOmit(ap.IDExtractor) {
		ap.IDExtractor = nil
	}
}

func (ap *AuthenticationPlugin) ExtractTo(api *apidef.APIDefinition) {
	api.CustomMiddleware.AuthCheck.Disabled = !ap.Enabled
	api.CustomMiddleware.AuthCheck.Name = ap.FunctionName
	api.CustomMiddleware.AuthCheck.Path = ap.Path
	api.CustomMiddleware.AuthCheck.RawBodyOnly = ap.RawBodyOnly
	api.CustomMiddleware.AuthCheck.RequireSession = ap.RequireSession

	if ap.IDExtractor == nil {
		ap.IDExtractor = &IDExtractor{}
		defer func() {
			ap.IDExtractor = nil
		}()
	}

	ap.IDExtractor.ExtractTo(api)
}

// IDExtractorConfig specifies the configuration for ID extractor.
type IDExtractorConfig struct {
	// HeaderName is the header name to extract ID from.
	// Used when Source is set to "header" and With is set to "value".
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config.header_name`.
	HeaderName string `bson:"headerName,omitempty" json:"headerName,omitempty"`
	// FormParamName is the form parameter name to extract ID from.
	// Used when Source is set to "form" and With is set to "value".
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config.form_param_name`.
	FormParamName string `bson:"formParamName,omitempty" json:"formParamName,omitempty"`
	// Regexp is the regular expression to match ID.
	// Used when With is set to "regex".
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config.regex_expression`.
	Regexp string `bson:"regexp,omitempty" json:"regexp,omitempty"`
	// RegexpMatchIndex is the index from which ID to be extracted after a match.
	// Default value is 0, ie if regexpMatchIndex is not provided ID is matched from index 0.
	// Used when With is set to "regex".
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config.regex_match_index`.
	RegexpMatchIndex int `bson:"regexpMatchIndex,omitempty" json:"regexpMatchIndex,omitempty"`
	// XPathExp is the xpath expression to match ID.
	// Used when With is set to "xpath".
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config.xpath_expression`.
	XPathExp string `bson:"xPathExp,omitempty" json:"xPathExp,omitempty"`
}

// Fill fills IDExtractorConfig from supplied classic APIDefinition.
func (id *IDExtractorConfig) Fill(api apidef.APIDefinition) {
	var classicIDExtractorConfig apidef.IDExtractorConfig
	err := mapstructure.Decode(api.CustomMiddleware.IdExtractor.ExtractorConfig, &classicIDExtractorConfig)
	if err != nil {
		log.WithError(err).Error("error while decoding IDExtractorConfig")
		return
	}

	*id = IDExtractorConfig{
		HeaderName:       classicIDExtractorConfig.HeaderName,
		FormParamName:    classicIDExtractorConfig.FormParamName,
		Regexp:           classicIDExtractorConfig.RegexExpression,
		RegexpMatchIndex: classicIDExtractorConfig.RegexMatchIndex,
		XPathExp:         classicIDExtractorConfig.XPathExpression,
	}
}

// ExtractTo extracts IDExtractorConfig into supplied classic API definition.
func (id *IDExtractorConfig) ExtractTo(api *apidef.APIDefinition) {
	classicIDExtractorConfig := apidef.IDExtractorConfig{
		HeaderName:      id.HeaderName,
		FormParamName:   id.FormParamName,
		RegexExpression: id.Regexp,
		RegexMatchIndex: id.RegexpMatchIndex,
		XPathExpression: id.XPathExp,
	}

	configData, err := json.Marshal(&classicIDExtractorConfig)
	if err != nil {
		log.WithError(err).Error("error while marshalling IDExtractorConfig")
		return
	}
	var extractorConfigMap map[string]interface{}
	err = json.Unmarshal(configData, &extractorConfigMap)
	if err != nil {
		log.WithError(err).Error("error while encoding IDExtractorConfig")
		return
	}

	if len(extractorConfigMap) == 0 {
		extractorConfigMap = nil
	}

	api.CustomMiddleware.IdExtractor.ExtractorConfig = extractorConfigMap
}

// IDExtractor configures ID Extractor.
type IDExtractor struct {
	// Enabled activates ID extractor with coprocess authentication.
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Source is the source from which ID to be extracted from.
	// Valid values are:
	// - `header` - Extract ID from a header
	// - `form` - Extract ID from a form parameter
	// - `body` - Extract ID from the request body
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extract_from`.
	Source apidef.IdExtractorSource `bson:"source" json:"source"` // required
	// With is the type of ID extractor to be used.
	// Valid values are:
	// - `value` - Extract ID from a value
	// - `xpath` - Extract ID using an XPath expression
	// - `regex` - Extract ID using a regular expression
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extract_with`.
	With apidef.IdExtractorType `bson:"with" json:"with"` // required
	// Config holds the configuration specific to ID extractor type mentioned via With.
	//
	// Tyk classic API definition: `custom_middleware.id_extractor.extractor_config`.
	Config *IDExtractorConfig `bson:"config" json:"config"` // required
}

// Fill fills IDExtractor from supplied classic APIDefinition.
func (id *IDExtractor) Fill(api apidef.APIDefinition) {
	id.Enabled = !api.CustomMiddleware.IdExtractor.Disabled
	id.Source = api.CustomMiddleware.IdExtractor.ExtractFrom
	id.With = api.CustomMiddleware.IdExtractor.ExtractWith

	if id.Config == nil {
		id.Config = &IDExtractorConfig{}
	}

	id.Config.Fill(api)
	if ShouldOmit(id.Config) {
		id.Config = nil
	}
}

// ExtractTo extracts IDExtractor into supplied classic API definition.
func (id *IDExtractor) ExtractTo(api *apidef.APIDefinition) {
	api.CustomMiddleware.IdExtractor.Disabled = !id.Enabled
	api.CustomMiddleware.IdExtractor.ExtractFrom = id.Source
	api.CustomMiddleware.IdExtractor.ExtractWith = id.With

	if id.Config == nil {
		id.Config = &IDExtractorConfig{}
		defer func() {
			id.Config = nil
		}()
	}

	id.Config.ExtractTo(api)
}
