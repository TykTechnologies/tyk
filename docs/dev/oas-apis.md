# Package oas

```go
import (
	"github.com/TykTechnologies/tyk/apidef/oas"
}
```

## Types

```go
// APIDef holds both OAS and Classic forms of an API definition.
type APIDef struct {
	// OAS contains the OAS API definition.
	OAS *OAS
	// Classic contains the Classic API definition.
	Classic *apidef.APIDefinition
}
```

```go
// Allowance describes allowance actions and behaviour.
type Allowance struct {
	// Enabled is a boolean flag, if set to `true`, then individual allowances (allow, block, ignore) will be enforced.
	Enabled bool `bson:"enabled" json:"enabled"`

	// IgnoreCase is a boolean flag, If set to `true`, checks for requests allowance will be case insensitive.
	IgnoreCase bool `bson:"ignoreCase,omitempty" json:"ignoreCase,omitempty"`
}
```

```go
// AllowanceType holds the valid allowance types values.
type AllowanceType int
```

```go
// AuthSource defines an authentication source.
type AuthSource struct {
	// Enabled activates the auth source.
	// Tyk classic API definition: `auth_configs[X].use_param/use_cookie`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name is the name of the auth source.
	// Tyk classic API definition: `auth_configs[X].param_name/cookie_name`
	Name string `bson:"name,omitempty" json:"name,omitempty"`
}
```

```go
// AuthSources defines authentication source configuration: headers, cookies and query parameters.
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
```

```go
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
	SecuritySchemes SecuritySchemes `bson:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`

	// CustomKeyLifetime contains configuration for the maximum retention period for tokens.
	CustomKeyLifetime *CustomKeyLifetime `bson:"customKeyLifetime,omitempty" json:"customKeyLifetime,omitempty"`
}
```

```go
// AuthenticationPlugin holds the configuration for custom authentication plugin.
type AuthenticationPlugin struct {
	// Enabled activates custom authentication plugin.
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// FunctionName is the name of authentication method.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to shared object file in case of goplugin mode or path to JS code in case of otto auth plugin.
	Path string `bson:"path" json:"path"`
	// RawBodyOnly if set to true, do not fill body in request or response object.
	RawBodyOnly bool `bson:"rawBodyOnly,omitempty" json:"rawBodyOnly,omitempty"`
	// IDExtractor configures ID extractor with coprocess custom authentication.
	IDExtractor *IDExtractor `bson:"idExtractor,omitempty" json:"idExtractor,omitempty"`
}
```

```go
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
```

```go
// BatchProcessing represents the configuration for enabling or disabling batch request support for an API.
type BatchProcessing struct {
	// Enabled determines whether batch request support is enabled or disabled for the API.
	Enabled bool `bson:"enabled" json:"enabled"` // required
}
```

```go
// CORS holds configuration for cross-origin resource sharing.
type CORS struct {
	// Enabled is a boolean flag, if set to `true`, this option enables CORS processing.
	//
	// Tyk classic API definition: `CORS.enable`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached. The default is 0 which stands for no max age.
	//
	// Tyk classic API definition: `CORS.max_age`.
	MaxAge int `bson:"maxAge,omitempty" json:"maxAge,omitempty"`

	// AllowCredentials indicates if the request can include user credentials like cookies,
	// HTTP authentication or client side SSL certificates.
	//
	// Tyk classic API definition: `CORS.allow_credentials`.
	AllowCredentials bool `bson:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`

	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS API specification.
	//
	// Tyk classic API definition: `CORS.exposed_headers`.
	ExposedHeaders []string `bson:"exposedHeaders,omitempty" json:"exposedHeaders,omitempty"`

	// AllowedHeaders holds a list of non simple headers the client is allowed to use with cross-domain requests.
	//
	// Tyk classic API definition: `CORS.allowed_headers`.
	AllowedHeaders []string `bson:"allowedHeaders,omitempty" json:"allowedHeaders,omitempty"`

	// OptionsPassthrough is a boolean flag. If set to `true`, it will proxy the CORS OPTIONS pre-flight
	// request directly to upstream, without authentication and any CORS checks. This means that pre-flight
	// requests generated by web-clients such as SwaggerUI or the Tyk Portal documentation system
	// will be able to test the API using trial keys.
	//
	// If your service handles CORS natively, then enable this option.
	//
	// Tyk classic API definition: `CORS.options_passthrough`.
	OptionsPassthrough bool `bson:"optionsPassthrough,omitempty" json:"optionsPassthrough,omitempty"`

	// Debug is a boolean flag, If set to `true`, this option produces log files for the CORS middleware.
	//
	// Tyk classic API definition: `CORS.debug`.
	Debug bool `bson:"debug,omitempty" json:"debug,omitempty"`

	// AllowedOrigins holds a list of origin domains to allow access from. Wildcards are also supported, e.g. `http://*.foo.com`
	//
	// Tyk classic API definition: `CORS.allowed_origins`.
	AllowedOrigins []string `bson:"allowedOrigins,omitempty" json:"allowedOrigins,omitempty"`

	// AllowedMethods holds a list of methods to allow access via.
	//
	// Tyk classic API definition: `CORS.allowed_methods`.
	AllowedMethods []string `bson:"allowedMethods,omitempty" json:"allowedMethods,omitempty"`
}
```

```go
// Cache holds configuration for caching the requests.
type Cache struct {
	// Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis
	// by explicitly setting the endpoint cache middleware.
	//
	// Tyk classic API definition: `cache_options.enable_cache`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Timeout is the TTL for a cached object in seconds.
	//
	// Tyk classic API definition: `cache_options.cache_timeout`
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`

	// CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions,
	// applies across versions.
	//
	// Tyk classic API definition: `cache_options.cache_all_safe_requests`
	CacheAllSafeRequests bool `bson:"cacheAllSafeRequests,omitempty" json:"cacheAllSafeRequests,omitempty"`

	// CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.
	//
	// Tyk classic API definition: `cache_options.cache_response_codes`
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`

	// CacheByHeaders allows header values to be used as part of the cache key.
	//
	// Tyk classic API definition: `cache_options.cache_by_headers`
	CacheByHeaders []string `bson:"cacheByHeaders,omitempty" json:"cacheByHeaders,omitempty"`

	// EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.
	//
	// Tyk classic API definition: `cache_options.enable_upstream_cache_control`
	EnableUpstreamCacheControl bool `bson:"enableUpstreamCacheControl,omitempty" json:"enableUpstreamCacheControl,omitempty"`

	// ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.
	//
	// Tyk classic API definition: `cache_options.cache_control_ttl_header`
	ControlTTLHeaderName string `bson:"controlTTLHeaderName,omitempty" json:"controlTTLHeaderName,omitempty"`
}
```

```go
// CachePlugin holds the configuration for the cache plugins.
type CachePlugin struct {
	// Enabled is a boolean flag. If set to `true`, the advanced caching plugin will be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`

	// CacheByRegex defines a regular expression used against the request body to produce a cache key.
	//
	// Example value: `\"id\":[^,]*` (quoted json value).
	CacheByRegex string `bson:"cacheByRegex,omitempty" json:"cacheByRegex,omitempty"`

	// CacheResponseCodes contains a list of valid response codes for responses that are okay to add to the cache.
	CacheResponseCodes []int `bson:"cacheResponseCodes,omitempty" json:"cacheResponseCodes,omitempty"`

	// Timeout is the TTL for the endpoint level caching in seconds. 0 means no caching.
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`
}
```

```go
// CertificatePinning holds the configuration about mapping of domains to pinned public keys.
type CertificatePinning struct {
	// Enabled is a boolean flag, if set to `true`, it enables certificate pinning for the API.
	//
	// Tyk classic API definition: `certificate_pinning_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.
	//
	// Tyk classic API definition: `pinned_public_keys`
	DomainToPublicKeysMapping PinnedPublicKeys `bson:"domainToPublicKeysMapping" json:"domainToPublicKeysMapping"`
}
```

```go
// CircuitBreaker holds configuration for the circuit breaker middleware.
// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*]`.
type CircuitBreaker struct {
	// Enabled activates the Circuit Breaker functionality.
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].disabled`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Threshold is the proportion from each `sampleSize` requests that must fail for the breaker to be tripped. This must be a value between 0.0 and 1.0. If `sampleSize` is 100 then a threshold of 0.4 means that the breaker will be tripped if 40 out of every 100 requests fails.
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].threshold_percent`.
	Threshold float64 `bson:"threshold" json:"threshold"`
	// SampleSize is the size of the circuit breaker sampling window. Combining this with `threshold` gives the failure rate required to trip the circuit breaker.
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].samples`.
	SampleSize int `bson:"sampleSize" json:"sampleSize"`
	// CoolDownPeriod is the period of time (in seconds) for which the circuit breaker will remain open before returning to service.
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].return_to_service_after`.
	CoolDownPeriod int `bson:"coolDownPeriod" json:"coolDownPeriod"`
	// HalfOpenStateEnabled , if enabled, allows some requests to pass through the circuit breaker during the cool down period. If Tyk detects that the path is now working, the circuit breaker will be automatically reset and traffic will be resumed to the upstream.
	// Tyk classic API definition: `version_data.versions..extended_paths.circuit_breakers[*].disable_half_open_state`.
	HalfOpenStateEnabled bool `bson:"halfOpenStateEnabled" json:"halfOpenStateEnabled"`
}
```

```go
// ClientAuthData holds the client ID and secret for OAuth2 authentication.
type ClientAuthData struct {
	// ClientID is the application's ID.
	ClientID string `bson:"clientId" json:"clientId"`
	// ClientSecret is the application's secret.
	ClientSecret string `bson:"clientSecret,omitempty" json:"clientSecret,omitempty"` // client secret is optional for password flow
}
```

```go
// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
type ClientCertificates struct {
	// Enabled activates static mTLS for the API.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Allowlist is the list of client certificates which are allowed.
	Allowlist []string `bson:"allowlist" json:"allowlist"`
}
```

```go
// ClientCredentials holds the configuration for OAuth2 Client Credentials flow.
type ClientCredentials struct {
	ClientAuthData
	// Header holds the configuration for the custom header to be used for OAuth authentication.
	Header *AuthSource `bson:"header" json:"header"`
	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string `bson:"tokenUrl" json:"tokenUrl"`
	// Scopes specifies optional requested permissions.
	Scopes []string `bson:"scopes,omitempty" json:"scopes,omitempty"`
	// ExtraMetadata holds the keys that we want to extract from the token and pass to the upstream.
	ExtraMetadata []string `bson:"extraMetadata" json:"extraMetadata,omitempty"`
}
```

```go
// ClientToPolicy contains a 1-1 mapping between Client ID and Policy ID.
type ClientToPolicy struct {
	// ClientID contains a Client ID.
	ClientID string `bson:"clientId,omitempty" json:"clientId,omitempty"`

	// PolicyID contains a Policy ID.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}
```

```go
// ContextVariables holds the configuration related to Tyk context variables.
type ContextVariables struct {
	// Enabled enables context variables to be passed to Tyk middlewares.
	// Tyk classic API definition: `enable_context_vars`.
	Enabled bool `json:"enabled" bson:"enabled"`
}
```

```go
// CustomAnalyticsPlugins is a list of CustomPlugin objects for analytics.
type CustomAnalyticsPlugins []CustomPlugin
```

```go
// CustomKeyLifetime contains configuration for custom key retention.
type CustomKeyLifetime struct {
	// Enabled enables custom maximum retention for keys for the API
	//
	// Tyk classic API definition: `disable_expire_analytics`.
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
	// Tyk classic API definition: `expire_analytics_after`.
	Value ReadableDuration `bson:"value" json:"value"`
	// RespectValidity ensures that Tyk respects the expiry configured in the key when the API level configuration grants a shorter lifetime.
	// That is, Redis waits until the key has expired before deleting it.
	RespectValidity bool `bson:"respectValidity,omitempty" json:"respectValidity,omitempty"`
}
```

```go
// CustomPlugin configures custom plugin.
type CustomPlugin struct {
	// Enabled activates the custom pre plugin.
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// FunctionName is the name of authentication method.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to shared object file in case of goplugin mode or path to JS code in case of otto auth plugin.
	Path string `bson:"path" json:"path"`
	// RawBodyOnly if set to true, do not fill body in request or response object.
	RawBodyOnly bool `bson:"rawBodyOnly,omitempty" json:"rawBodyOnly,omitempty"`
	// RequireSession if set to true passes down the session information for plugins after authentication.
	// RequireSession is used only with JSVM custom middleware.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
}
```

```go
// CustomPluginAuthentication holds configuration for custom plugins.
type CustomPluginAuthentication struct {
	// Enabled activates the CustomPluginAuthentication authentication mode.
	//
	// Tyk classic API definition: `enable_coprocess_auth`/`use_go_plugin_auth`.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Config contains configuration related to custom authentication plugin.
	// Tyk classic API definition: `custom_middleware.auth_check`.
	Config *AuthenticationPlugin `bson:"config,omitempty" json:"config,omitempty"`

	// Authentication token sources (header, cookie, query).
	// valid only when driver is coprocess.
	AuthSources `bson:",inline" json:",inline"`
}
```

```go
// CustomPlugins is a list of CustomPlugin objects.
type CustomPlugins []CustomPlugin
```

```go
// DetailedActivityLogs holds the configuration related to recording detailed analytics.
type DetailedActivityLogs struct {
	// Enabled activates detailed activity logs.
	//
	// Tyk classic API definition: `enable_detailed_recording`
	Enabled bool `bson:"enabled" json:"enabled"`
}
```

```go
// DetailedTracing holds the configuration of the detailed tracing.
type DetailedTracing struct {
	// Enabled activates detailed tracing.
	Enabled bool `bson:"enabled" json:"enabled"`
}
```

```go
// Domain holds the configuration of the domain name the server should listen on.
type Domain struct {
	// Enabled allow/disallow the usage of the domain.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of the domain.
	Name string `bson:"name" json:"name"`
	// Certificates defines a field for specifying certificate IDs or file paths
	// that the Gateway can utilise to dynamically load certificates for your custom domain.
	//
	// Tyk classic API definition: `certificates`
	Certificates []string `bson:"certificates,omitempty" json:"certificates,omitempty"`
}
```

```go
// DomainToCertificate holds a single mapping of domain name into a certificate.
type DomainToCertificate struct {
	// Domain contains the domain name.
	Domain string `bson:"domain" json:"domain"`

	// Certificate contains the certificate mapped to the domain.
	Certificate string `bson:"certificate" json:"certificate"`
}
```

```go
// EndpointPostPlugin contains endpoint level post plugin configuration.
type EndpointPostPlugin struct {
	// Enabled activates post plugin.
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Name is the name of plugin function to be executed.
	// Deprecated: Use FunctionName instead.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// FunctionName is the name of plugin function to be executed.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to plugin.
	Path string `bson:"path" json:"path"` // required.
}
```

```go
// EndpointPostPlugins is a list of EndpointPostPlugins. It's used where multiple plugins can be run.
type EndpointPostPlugins []EndpointPostPlugin
```

```go
// EnforceTimeout holds the configuration for enforcing request timeouts.
type EnforceTimeout struct {
	// Enabled is a boolean flag. If set to `true`, requests will enforce a configured timeout.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Value is the configured timeout in seconds.
	Value int `bson:"value" json:"value"`
}
```

```go
// EventHandler holds information about individual event to be configured on the API.
type EventHandler struct {
	// Enabled enables the event handler.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Trigger specifies the TykEvent that should trigger the event handler.
	Trigger event.Event `json:"trigger" bson:"trigger"`
	// Kind specifies the action to be taken on the event trigger.
	Kind Kind `json:"type" bson:"type"` // json tag is changed as per contract
	// ID is the ID of event handler in storage.
	ID string `json:"id,omitempty" bson:"id,omitempty"`
	// Name is the name of event handler.
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Webhook contains WebhookEvent configs. Encoding and decoding is handled by the custom marshaller.
	Webhook WebhookEvent `bson:"-" json:"-"`

	// JSVMEvent holds information about JavaScript VM events.
	JSVMEvent JSVMEvent `bson:"-" json:"-"`
}
```

```go
// EventHandlers holds the list of events to be processed for the API.
type EventHandlers []EventHandler
```

```go
// ExternalOAuth holds configuration for an external OAuth provider.
// ExternalOAuth support will be deprecated starting from 5.7.0.
// To avoid any disruptions, we recommend that you use JSON Web Token (JWT) instead,
// as explained in https://tyk.io/docs/basic-config-and-security/security/authentication-authorization/ext-oauth-middleware/.
type ExternalOAuth struct {
	// Enabled activates external oauth functionality.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources configures the source for the authentication token.
	AuthSources `bson:",inline" json:",inline"`

	// Providers is used to configure OAuth providers.
	Providers []OAuthProvider `bson:"providers" json:"providers"` // required
}
```

```go
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
```

```go
// FromOASExamples configures mock responses that should be returned from OAS example responses.
type FromOASExamples struct {
	// Enabled activates getting a mock response from OAS examples or schemas documented in OAS.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Code is the default HTTP response code that the gateway reads from the path responses documented in OAS.
	Code int `bson:"code,omitempty" json:"code,omitempty"`
	// ContentType is the default HTTP response body type that the gateway reads from the path responses documented in OAS.
	ContentType string `bson:"contentType,omitempty" json:"contentType,omitempty"`
	// ExampleName is the default example name among multiple path response examples documented in OAS.
	ExampleName string `bson:"exampleName,omitempty" json:"exampleName,omitempty"`
}
```

```go
// GatewayTags holds a list of segment tags that should apply for a gateway.
type GatewayTags struct {
	// Enabled activates use of segment tags.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Tags contains a list of segment tags.
	Tags []string `bson:"tags" json:"tags"`
}
```

```go
// Global contains configuration that affects the whole API (all endpoints).
type Global struct {
	// PluginConfig contains the common configuration for custom plugins.
	PluginConfig *PluginConfig `bson:"pluginConfig,omitempty" json:"pluginConfig,omitempty"`

	// CORS contains the configuration related to Cross Origin Resource Sharing.
	// Tyk classic API definition: `CORS`.
	CORS *CORS `bson:"cors,omitempty" json:"cors,omitempty"`

	// PrePlugin contains configuration related to the custom plugin that is run before authentication.
	// Deprecated: Use PrePlugins instead.
	PrePlugin *PrePlugin `bson:"prePlugin,omitempty" json:"prePlugin,omitempty"`

	// PrePlugins contains configuration related to the custom plugin that is run before authentication.
	// Tyk classic API definition: `custom_middleware.pre`.
	PrePlugins CustomPlugins `bson:"prePlugins,omitempty" json:"prePlugins,omitempty"`

	// PostAuthenticationPlugin contains configuration related to the custom plugin that is run immediately after authentication.
	// Deprecated: Use PostAuthenticationPlugins instead.
	PostAuthenticationPlugin *PostAuthenticationPlugin `bson:"postAuthenticationPlugin,omitempty" json:"postAuthenticationPlugin,omitempty"`

	// PostAuthenticationPlugins contains configuration related to the custom plugin that is run immediately after authentication.
	// Tyk classic API definition: `custom_middleware.post_key_auth`.
	PostAuthenticationPlugins CustomPlugins `bson:"postAuthenticationPlugins,omitempty" json:"postAuthenticationPlugins,omitempty"`

	// PostPlugin contains configuration related to the custom plugin that is run immediately prior to proxying the request to the upstream.
	// Deprecated: Use PostPlugins instead.
	PostPlugin *PostPlugin `bson:"postPlugin,omitempty" json:"postPlugin,omitempty"`

	// PostPlugins contains configuration related to the custom plugin that is run immediately prior to proxying the request to the upstream.
	// Tyk classic API definition: `custom_middleware.post`.
	PostPlugins CustomPlugins `bson:"postPlugins,omitempty" json:"postPlugins,omitempty"`

	// ResponsePlugin contains configuration related to the custom plugin that is run during processing of the response from the upstream service.
	// Deprecated: Use ResponsePlugins instead.
	ResponsePlugin *ResponsePlugin `bson:"responsePlugin,omitempty" json:"responsePlugin,omitempty"`

	// ResponsePlugins contains configuration related to the custom plugin that is run during processing of the response from the upstream service.
	//
	// Tyk classic API definition: `custom_middleware.response`.
	ResponsePlugins CustomPlugins `bson:"responsePlugins,omitempty" json:"responsePlugins,omitempty"`

	// Cache contains the configurations related to caching.
	// Tyk classic API definition: `cache_options`.
	Cache *Cache `bson:"cache,omitempty" json:"cache,omitempty"`

	// TransformRequestHeaders contains the configurations related to API level request header transformation.
	// Tyk classic API definition: `global_headers`/`global_headers_remove`.
	TransformRequestHeaders *TransformHeaders `bson:"transformRequestHeaders,omitempty" json:"transformRequestHeaders,omitempty"`

	// TransformResponseHeaders contains the configurations related to API level response header transformation.
	// Tyk classic API definition: `global_response_headers`/`global_response_headers_remove`.
	TransformResponseHeaders *TransformHeaders `bson:"transformResponseHeaders,omitempty" json:"transformResponseHeaders,omitempty"`

	// ContextVariables contains the configuration related to Tyk context variables.
	ContextVariables *ContextVariables `bson:"contextVariables,omitempty" json:"contextVariables,omitempty"`

	// TrafficLogs contains the configurations related to API level log analytics.
	TrafficLogs *TrafficLogs `bson:"trafficLogs,omitempty" json:"trafficLogs,omitempty"`

	// RequestSizeLimit contains the configuration related to limiting the global request size.
	RequestSizeLimit *GlobalRequestSizeLimit `bson:"requestSizeLimit,omitempty" json:"requestSizeLimit,omitempty"`
}
```

```go
// GlobalRequestSizeLimit holds configuration about the global limits for request sizes.
type GlobalRequestSizeLimit struct {
	// Enabled activates the Request Size Limit.
	// Tyk classic API definition: `version_data.versions..global_size_limit_disabled`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Value contains the value of the request size limit.
	// Tyk classic API definition: `version_data.versions..global_size_limit`.
	Value int64 `bson:"value" json:"value"`
}
```

```go
// HMAC holds the configuration for the HMAC authentication mode.
type HMAC struct {
	// Enabled activates the HMAC authentication mode.
	// Tyk classic API definition: `enable_signature_checking`
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
	// Tyk classic API definition: `hmac_allowed_algorithms`
	AllowedAlgorithms []string `bson:"allowedAlgorithms,omitempty" json:"allowedAlgorithms,omitempty"`

	// AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
	// The default value is `0`, which deactivates clock skew checks.
	// Tyk classic API definition: `hmac_allowed_clock_skew`
	AllowedClockSkew float64 `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
}
```

```go
// Header holds a header name and value pair.
type Header struct {
	// Name is the name of the header.
	Name string `bson:"name" json:"name"`
	// Value is the value of the header.
	Value string `bson:"value" json:"value"`
}
```

```go
// Headers is an array of Header.
type Headers []Header
```

```go
// IDExtractor configures ID Extractor.
type IDExtractor struct {
	// Enabled activates ID extractor with coprocess authentication.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Source is the source from which ID to be extracted from.
	Source apidef.IdExtractorSource `bson:"source" json:"source"` // required
	// With is the type of ID extractor to be used.
	With apidef.IdExtractorType `bson:"with" json:"with"` // required
	// Config holds the configuration specific to ID extractor type mentioned via With.
	Config *IDExtractorConfig `bson:"config" json:"config"` // required
}
```

```go
// IDExtractorConfig specifies the configuration for ID extractor.
type IDExtractorConfig struct {
	// HeaderName is the header name to extract ID from.
	HeaderName string `bson:"headerName,omitempty" json:"headerName,omitempty"`
	// FormParamName is the form parameter name to extract ID from.
	FormParamName string `bson:"formParamName,omitempty" json:"formParamName,omitempty"`
	// Regexp is the regular expression to match ID.
	Regexp string `bson:"regexp,omitempty" json:"regexp,omitempty"`
	// RegexpMatchIndex is the index from which ID to be extracted after a match.
	// Default value is 0, ie if regexpMatchIndex is not provided ID is matched from index 0.
	RegexpMatchIndex int `bson:"regexpMatchIndex,omitempty" json:"regexpMatchIndex,omitempty"`
	// XPathExp is the xpath expression to match ID.
	XPathExp string `bson:"xPathExp,omitempty" json:"xPathExp,omitempty"`
}
```

```go
// IPAccessControl represents IP access control configuration.
type IPAccessControl struct {
	// Enabled indicates whether IP access control is enabled.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Allow is a list of allowed IP addresses or CIDR blocks (e.g. "192.168.1.0/24").
	// Note that if an IP address is present in both Allow and Block, the Block rule will take precedence.
	Allow []string `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block is a list of blocked IP addresses or CIDR blocks (e.g. "192.168.1.100/32").
	// If an IP address is present in both Allow and Block, the Block rule will take precedence.
	Block []string `bson:"block,omitempty" json:"block,omitempty"`
}
```

```go
// Info contains the main metadata for the API definition.
type Info struct {
	// ID is the unique identifier of the API within Tyk.
	// Tyk classic API definition: `api_id`
	ID string `bson:"id" json:"id,omitempty"`
	// DBID is the unique identifier of the API within the Tyk database.
	// Tyk classic API definition: `id`
	DBID model.ObjectID `bson:"dbId" json:"dbId,omitempty"`
	// OrgID is the ID of the organisation which the API belongs to.
	// Tyk classic API definition: `org_id`
	OrgID string `bson:"orgId" json:"orgId,omitempty"`
	// Name is the name of the API.
	// Tyk classic API definition: `name`
	Name string `bson:"name" json:"name"` // required
	// Expiration date.
	Expiration string `bson:"expiration,omitempty" json:"expiration,omitempty"`
	// State holds configuration for API definition states (active, internal).
	State State `bson:"state" json:"state"` // required
	// Versioning holds configuration for API versioning.
	Versioning *Versioning `bson:"versioning,omitempty" json:"versioning,omitempty"`
}
```

```go
// Internal holds the endpoint configuration, configuring the endpoint for internal requests.
// Tyk classic API definition: `version_data.versions...extended_paths.internal[*]`.
type Internal struct {
	// Enabled if set to true makes the endpoint available only for internal requests.
	Enabled bool `bson:"enabled" json:"enabled"`
}
```

```go
// Introspection holds configuration for OAuth token introspection.
type Introspection struct {
	// Enabled activates OAuth access token validation by introspection to a third party.
	Enabled bool `bson:"enabled" json:"enabled"`
	// URL is the URL of the third party provider's introspection endpoint.
	URL string `bson:"url" json:"url"`
	// ClientID is the public identifier for the client, acquired from the third party.
	ClientID string `bson:"clientId" json:"clientId"`
	// ClientSecret is a secret known only to the client and the authorisation server, acquired from the third party.
	ClientSecret string `bson:"clientSecret" json:"clientSecret"`
	// IdentityBaseField is the key showing where to find the user id in the claims. If it is empty, the `sub` key is looked at.
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`
	// Cache is the caching mechanism for introspection responses.
	Cache *IntrospectionCache `bson:"cache,omitempty" json:"cache,omitempty"`
}
```

```go
// IntrospectionCache holds configuration for caching introspection requests.
type IntrospectionCache struct {
	// Enabled activates the caching mechanism for introspection responses.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Timeout is the duration in seconds of how long the cached value stays.
	// For introspection caching, it is suggested to use a short interval.
	Timeout int64 `bson:"timeout" json:"timeout"`
}
```

```go
// JSVMEvent represents a JavaScript VM event configuration for event handlers.
type JSVMEvent struct {
	// FunctionName specifies the JavaScript function name to be executed.
	FunctionName string `json:"functionName" bson:"functionName"`
	// Path specifies the path to the JavaScript file containing the function.
	Path string `json:"path" bson:"path"`
}
```

```go
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

	// SigningMethod contains the signing method to use for the JWT.
	//
	// Tyk classic API definition: `jwt_signing_method`
	SigningMethod string `bson:"signingMethod,omitempty" json:"signingMethod,omitempty"`

	// IdentityBaseField specifies the claim name uniquely identifying the subject of the JWT.
	// The identity fields that are checked in order are: `kid`, IdentityBaseField, `sub`.
	//
	// Tyk classic API definition: `jwt_identity_base_field`
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`

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
	IssuedAtValidationSkew uint64 `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`

	// NotBeforeValidationSkew contains the duration in seconds for which token validity can predate the current time during the request.
	NotBeforeValidationSkew uint64 `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`

	// ExpiresAtValidationSkew contains the duration in seconds for which the token can be expired before we consider it expired.
	ExpiresAtValidationSkew uint64 `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`

	// IDPClientIDMappingDisabled prevents Tyk from automatically detecting the use of certain IDPs based on standard claims
	// that they include in the JWT: `client_id`, `cid`, `clientId`. Setting this flag to `true` disables the mapping and avoids
	// accidentally misidentifying the use of one of these IDPs if one of their standard values is configured in your JWT.
	IDPClientIDMappingDisabled bool `bson:"idpClientIdMappingDisabled,omitempty" json:"idpClientIdMappingDisabled,omitempty"`
}
```

```go
// JWTValidation holds configuration for validating access tokens by inspecing them
// against a third party API, usually one provided by the IDP.
type JWTValidation struct {
	// Enabled activates OAuth access token validation.
	Enabled bool `bson:"enabled" json:"enabled"`

	// SigningMethod to verify signing method used in jwt - allowed values HMAC/RSA/ECDSA.
	SigningMethod string `bson:"signingMethod" json:"signingMethod"`

	// Source is the secret to verify signature. Valid values are:
	//
	// - a base64 encoded static secret,
	// - a valid JWK URL in plain text,
	// - a valid JWK URL in base64 encoded format.
	Source string `bson:"source" json:"source"`

	// IdentityBaseField is the identity claim name.
	IdentityBaseField string `bson:"identityBaseField,omitempty" json:"identityBaseField,omitempty"`

	// IssuedAtValidationSkew is the clock skew to be considered while validating the iat claim.
	IssuedAtValidationSkew uint64 `bson:"issuedAtValidationSkew,omitempty" json:"issuedAtValidationSkew,omitempty"`

	// NotBeforeValidationSkew is the clock skew to be considered while validating the nbf claim.
	NotBeforeValidationSkew uint64 `bson:"notBeforeValidationSkew,omitempty" json:"notBeforeValidationSkew,omitempty"`

	// ExpiresAtValidationSkew is the clock skew to be considered while validating the exp claim.
	ExpiresAtValidationSkew uint64 `bson:"expiresAtValidationSkew,omitempty" json:"expiresAtValidationSkew,omitempty"`
}
```

```go
// Kind is an alias maintained to be used in imports.
type Kind = event.Kind
```

```go
// ListenPath is the base path on Tyk to which requests for this API
// should be sent. Tyk listens out for any requests coming into the host at
// this path, on the port that Tyk is configured to run on and processes
// these accordingly.
type ListenPath struct {
	// Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.
	// Tyk classic API definition: `proxy.listen_path`
	Value string `bson:"value" json:"value"` // required

	// Strip removes the inbound listen path (as accessed by the client) when generating the outbound request for the upstream service.
	//
	// For example, consider the scenario where the Tyk base address is `http://acme.com/', the listen path is `example/` and the upstream URL is `http://httpbin.org/`:
	//
	// - If the client application sends a request to `http://acme.com/example/get` then the request will be proxied to `http://httpbin.org/example/get`
	// - If stripListenPath is set to `true`, the `example` listen path is removed and the request would be proxied to `http://httpbin.org/get`.
	//
	// Tyk classic API definition: `proxy.strip_listen_path`
	Strip bool `bson:"strip,omitempty" json:"strip,omitempty"`
}
```

```go
// LoadBalancing represents the configuration for load balancing between multiple upstream targets.
type LoadBalancing struct {
	// Enabled determines if load balancing is active.
	Enabled bool `json:"enabled" bson:"enabled"` // required
	// Targets defines the list of targets with their respective weights for load balancing.
	Targets []LoadBalancingTarget `json:"targets,omitempty" bson:"targets,omitempty"`
}
```

```go
// LoadBalancingTarget represents a single upstream target for load balancing with a URL and an associated weight.
type LoadBalancingTarget struct {
	// URL specifies the upstream target URL for load balancing, represented as a string.
	URL string `json:"url" bson:"url"` // required
	// Weight specifies the relative distribution factor for load balancing, determining the importance of this target.
	Weight int `json:"weight" bson:"weight"` // required
}
```

```go
// Middleware holds configuration for Tyk's native middleware.
type Middleware struct {
	// Global contains configuration for middleware that affects the whole API (all endpoints).
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`

	// Operations contains configuration for middleware that can be applied to individual endpoints within the API (per-endpoint).
	Operations Operations `bson:"operations,omitempty" json:"operations,omitempty"`
}
```

```go
// MockResponse configures the mock responses.
type MockResponse struct {
	// Enabled activates the mock response middleware.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Code is the HTTP response code that will be returned.
	Code int `bson:"code,omitempty" json:"code,omitempty"`
	// Body is the HTTP response body that will be returned.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
	// Headers are the HTTP response headers that will be returned.
	Headers Headers `bson:"headers,omitempty" json:"headers,omitempty"`
	// FromOASExamples is the configuration to extract a mock response from OAS documentation.
	FromOASExamples *FromOASExamples `bson:"fromOASExamples,omitempty" json:"fromOASExamples,omitempty"`
}
```

```go
// MutualTLS contains the configuration for establishing a mutual TLS connection between Tyk and the upstream server.
type MutualTLS struct {
	// Enabled activates upstream mutual TLS for the API.
	// Tyk classic API definition: `upstream_certificates_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToCertificates maintains the mapping of domain to certificate.
	// Tyk classic API definition: `upstream_certificates`
	DomainToCertificates []DomainToCertificate `bson:"domainToCertificateMapping" json:"domainToCertificateMapping"`
}
```

```go
// Notifications holds configuration for updates to keys.
type Notifications struct {
	// SharedSecret is the shared secret used in the notification request.
	SharedSecret string `bson:"sharedSecret,omitempty" json:"sharedSecret,omitempty"`
	// OnKeyChangeURL is the URL a request will be triggered against.
	OnKeyChangeURL string `bson:"onKeyChangeUrl,omitempty" json:"onKeyChangeUrl,omitempty"`
}
```

```go
// OAS holds the upstream OAS definition as well as adds functionality like custom JSON marshalling.
type OAS struct {
	openapi3.T
}
```

```go
// OAuth configures the OAuth middleware.
type OAuth struct {
	// Enabled activates the OAuth middleware.
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// AuthSources configures the sources for OAuth credentials.
	AuthSources `bson:",inline" json:",inline"`

	// AllowedAuthorizeTypes is an array of OAuth authorization types.
	AllowedAuthorizeTypes []osin.AuthorizeRequestType `bson:"allowedAuthorizeTypes,omitempty" json:"allowedAuthorizeTypes,omitempty"`

	// RefreshToken enables clients using a refresh token to get a new bearer access token.
	RefreshToken bool `bson:"refreshToken,omitempty" json:"refreshToken,omitempty"`

	// AuthLoginRedirect configures a URL to redirect to after a successful login.
	AuthLoginRedirect string `bson:"authLoginRedirect,omitempty" json:"authLoginRedirect,omitempty"`

	// Notifications configures a URL trigger on key changes.
	Notifications *Notifications `bson:"notifications,omitempty" json:"notifications,omitempty"`
}
```

```go
// OAuthProvider holds the configuration for validation and introspection of OAuth tokens.
type OAuthProvider struct {
	// JWT configures JWT validation.
	JWT *JWTValidation `bson:"jwt,omitempty" json:"jwt,omitempty"`
	// Introspection configures token introspection.
	Introspection *Introspection `bson:"introspection,omitempty" json:"introspection,omitempty"`
}
```

```go
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
```

```go
// OldOAS serves for data model migration/conversion purposes (gorm).
type OldOAS struct {
	openapifork.T
}
```

```go
// Operation holds a request operation configuration, allowances, tranformations, caching, timeouts and validation.
type Operation struct {
	// Allow request by allowance.
	Allow *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block request by allowance.
	Block *Allowance `bson:"block,omitempty" json:"block,omitempty"`

	// IgnoreAuthentication ignores authentication on request by allowance.
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`

	// Internal makes the endpoint only respond to internal requests.
	Internal *Internal `bson:"internal,omitempty" json:"internal,omitempty"`

	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`

	// TransformRequestBody allows you to transform request body.
	// When both `path` and `body` are provided, body would take precedence.
	TransformRequestBody *TransformBody `bson:"transformRequestBody,omitempty" json:"transformRequestBody,omitempty"`

	// TransformResponseBody allows you to transform response body.
	// When both `path` and `body` are provided, body would take precedence.
	TransformResponseBody *TransformBody `bson:"transformResponseBody,omitempty" json:"transformResponseBody,omitempty"`

	// TransformRequestHeaders allows you to transform request headers.
	TransformRequestHeaders *TransformHeaders `bson:"transformRequestHeaders,omitempty" json:"transformRequestHeaders,omitempty"`

	// TransformResponseHeaders allows you to transform response headers.
	TransformResponseHeaders *TransformHeaders `bson:"transformResponseHeaders,omitempty" json:"transformResponseHeaders,omitempty"`

	// URLRewrite contains the URL rewriting configuration.
	URLRewrite *URLRewrite `bson:"urlRewrite,omitempty" json:"urlRewrite,omitempty"`

	// Cache contains the caching plugin configuration.
	Cache *CachePlugin `bson:"cache,omitempty" json:"cache,omitempty"`

	// EnforceTimeout contains the request timeout configuration.
	EnforceTimeout *EnforceTimeout `bson:"enforceTimeout,omitempty" json:"enforceTimeout,omitempty"`

	// ValidateRequest contains the request validation configuration.
	ValidateRequest *ValidateRequest `bson:"validateRequest,omitempty" json:"validateRequest,omitempty"`

	// MockResponse contains the mock response configuration.
	MockResponse *MockResponse `bson:"mockResponse,omitempty" json:"mockResponse,omitempty"`

	// VirtualEndpoint contains virtual endpoint configuration.
	VirtualEndpoint *VirtualEndpoint `bson:"virtualEndpoint,omitempty" json:"virtualEndpoint,omitempty"`

	// PostPlugins contains endpoint level post plugins configuration.
	PostPlugins EndpointPostPlugins `bson:"postPlugins,omitempty" json:"postPlugins,omitempty"`

	// CircuitBreaker contains the configuration for the circuit breaker functionality.
	CircuitBreaker *CircuitBreaker `bson:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// TrackEndpoint contains the configuration for enabling analytics and logs.
	TrackEndpoint *TrackEndpoint `bson:"trackEndpoint,omitempty" json:"trackEndpoint,omitempty"`

	// DoNotTrackEndpoint contains the configuration for disabling analytics and logs.
	DoNotTrackEndpoint *TrackEndpoint `bson:"doNotTrackEndpoint,omitempty" json:"doNotTrackEndpoint,omitempty"`

	// RequestSizeLimit limits the maximum allowed size of the request body in bytes.
	RequestSizeLimit *RequestSizeLimit `bson:"requestSizeLimit,omitempty" json:"requestSizeLimit,omitempty"`

	// RateLimit contains endpoint level rate limit configuration.
	RateLimit *RateLimitEndpoint `bson:"rateLimit,omitempty" json:"rateLimit,omitempty"`
}
```

```go
// Operations holds Operation definitions.
type Operations map[string]*Operation
```

```go
// PasswordAuthentication holds the configuration for upstream OAuth2 password authentication flow.
type PasswordAuthentication struct {
	ClientAuthData
	// Header holds the configuration for the custom header to be used for OAuth authentication.
	Header *AuthSource `bson:"header" json:"header"`
	// Username is the username to be used for upstream OAuth2 password authentication.
	Username string `bson:"username" json:"username"`
	// Password is the password to be used for upstream OAuth2 password authentication.
	Password string `bson:"password" json:"password"`
	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string `bson:"tokenUrl" json:"tokenUrl"`
	// Scopes specifies optional requested permissions.
	Scopes []string `bson:"scopes" json:"scopes,omitempty"`
	// ExtraMetadata holds the keys that we want to extract from the token and pass to the upstream.
	ExtraMetadata []string `bson:"extraMetadata" json:"extraMetadata,omitempty"`
}
```

```go
// Path holds plugin configurations for HTTP method verbs.
type Path struct {
	// Delete holds plugin configuration for DELETE requests.
	Delete *Plugins `bson:"DELETE,omitempty" json:"DELETE,omitempty"`
	// Get holds plugin configuration for GET requests.
	Get *Plugins `bson:"GET,omitempty" json:"GET,omitempty"`
	// Head holds plugin configuration for HEAD requests.
	Head *Plugins `bson:"HEAD,omitempty" json:"HEAD,omitempty"`
	// Options holds plugin configuration for OPTIONS requests.
	Options *Plugins `bson:"OPTIONS,omitempty" json:"OPTIONS,omitempty"`
	// Patch holds plugin configuration for PATCH requests.
	Patch *Plugins `bson:"PATCH,omitempty" json:"PATCH,omitempty"`
	// Post holds plugin configuration for POST requests.
	Post *Plugins `bson:"POST,omitempty" json:"POST,omitempty"`
	// Put holds plugin configuration for PUT requests.
	Put *Plugins `bson:"PUT,omitempty" json:"PUT,omitempty"`
	// Trace holds plugin configuration for TRACE requests.
	Trace *Plugins `bson:"TRACE,omitempty" json:"TRACE,omitempty"`
	// Connect holds plugin configuration for CONNECT requests.
	Connect *Plugins `bson:"CONNECT,omitempty" json:"CONNECT,omitempty"`
}
```

```go
// Paths is a mapping of API endpoints to Path plugin configurations.
type Paths map[string]*Path
```

```go
// PinnedPublicKey contains a mapping from the domain name into a list of public keys.
type PinnedPublicKey struct {
	// Domain contains the domain name.
	Domain string `bson:"domain" json:"domain"`

	// PublicKeys contains a list of the public keys pinned to the domain name.
	PublicKeys []string `bson:"publicKeys" json:"publicKeys"`
}
```

```go
// PinnedPublicKeys is a list of domains and pinned public keys for them.
type PinnedPublicKeys []PinnedPublicKey
```

```go
// PluginBundle holds configuration for custom plugins.
type PluginBundle struct {
	// Enabled activates the custom plugin bundles.
	//
	// Tyk classic API definition: `custom_middleware_bundle_disabled`
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Path is the path suffix to construct the URL to fetch plugin bundle from.
	// Path will be suffixed to `bundle_base_url` in gateway config.
	Path string `bson:"path" json:"path"` // required.
}
```

```go
// PluginConfig holds configuration for custom plugins.
type PluginConfig struct {
	// Driver configures which custom plugin driver to use.
	// The value should be set to one of the following:
	//
	// - `otto`,
	// - `python`,
	// - `lua`,
	// - `grpc`,
	// - `goplugin`.
	//
	// Tyk classic API definition: `custom_middleware.driver`.
	Driver apidef.MiddlewareDriver `bson:"driver,omitempty" json:"driver,omitempty"`

	// Bundle configures custom plugin bundles.
	Bundle *PluginBundle `bson:"bundle,omitempty" json:"bundle,omitempty"`

	// Data configures custom plugin data.
	Data *PluginConfigData `bson:"data,omitempty" json:"data,omitempty"`
}
```

```go
// PluginConfigData configures config data for custom plugins.
type PluginConfigData struct {
	// Enabled activates custom plugin config data.
	Enabled bool `bson:"enabled" json:"enabled"` // required.

	// Value is the value of custom plugin config data.
	Value map[string]interface{} `bson:"value" json:"value"` // required.
}
```

```go
// Plugins configures common settings for each plugin, allowances, transforms, caching and timeouts.
type Plugins struct {
	// Allow request by allowance.
	Allow *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block request by allowance.
	Block *Allowance `bson:"block,omitempty" json:"block,omitempty"`

	// IgnoreAuthentication ignores authentication on request by allowance.
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`

	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`

	// Cache allows you to cache the server side response.
	Cache *CachePlugin `bson:"cache,omitempty" json:"cache,omitempty"`

	// EnforceTimeout allows you to configure a request timeout.
	EnforceTimeout *EnforceTimeout `bson:"enforcedTimeout,omitempty" json:"enforcedTimeout,omitempty"`
}
```

```go
// PostAuthenticationPlugin configures post authentication plugins.
type PostAuthenticationPlugin struct {
	// Plugins configures custom plugins to be run on pre authentication stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}
```

```go
// PostPlugin configures post plugins.
type PostPlugin struct {
	// Plugins configures custom plugins to be run on post stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}
```

```go
// PrePlugin configures pre-request plugins.
// Pre-request plugins are executed before the request is sent to the
// upstream target and before any authentication information is extracted
// from the header or parameter list of the request.
type PrePlugin struct {
	// Plugins configures custom plugins to be run on pre authentication stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}
```

```go
// PreserveHostHeader holds the configuration for preserving the host header.
type PreserveHostHeader struct {
	// Enabled activates preserving the host header.
	Enabled bool `json:"enabled" bson:"enabled"`
}
```

```go
// Provider defines an issuer to validate and the Client ID to Policy ID mappings.
type Provider struct {
	// Issuer contains a validation value for the issuer claim, usually a domain name e.g. `accounts.google.com` or similar.
	Issuer string `bson:"issuer,omitempty" json:"issuer,omitempty"`

	// ClientToPolicyMapping contains mappings of Client IDs to Policy IDs.
	ClientToPolicyMapping []ClientToPolicy `bson:"clientToPolicyMapping,omitempty" json:"clientToPolicyMapping,omitempty"`
}
```

```go
// Proxy contains the configuration for an internal proxy.
// Tyk classic API definition: `proxy.proxy_url`
type Proxy struct {
	// Enabled determines if the proxy is active.
	Enabled bool `bson:"enabled" json:"enabled"`

	// URL specifies the URL of the internal proxy.
	URL string `bson:"url" json:"url"`
}
```

```go
// RateLimit holds the configurations related to rate limit.
// The API-level rate limit applies a base-line limit on the frequency of requests to the upstream service for all endpoints. The frequency of requests is configured in two parts: the time interval and the number of requests that can be made during each interval.
// Tyk classic API definition: `global_rate_limit`.
type RateLimit struct {
	// Enabled activates API level rate limiting for this API.
	//
	// Tyk classic API definition: `!disable_rate_limit`.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Rate specifies the number of requests that can be passed to the upstream in each time interval (`per`).
	// This field sets the limit on the frequency of requests to ensure controlled
	// resource access or to prevent abuse. The rate is defined as an integer value.
	//
	// A higher value indicates a higher number of allowed requests in the given
	// time frame. For instance, if `Per` is set to `1m` (one minute), a Rate of `100`
	// means up to 100 requests can be made per minute.
	//
	// Tyk classic API definition: `global_rate_limit.rate`.
	Rate int `json:"rate" bson:"rate"`
	// Per defines the time interval for rate limiting using shorthand notation.
	// The value of Per is a string that specifies the interval in a compact form,
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
	// An empty value is interpreted as "0s", implying no rate limiting interval, which disables the API-level rate limit.
	// It's important to format the string correctly, as invalid formats will
	// be considered as 0s/empty.
	//
	// Tyk classic API definition: `global_rate_limit.per`.
	Per ReadableDuration `json:"per" bson:"per"`
}
```

```go
// RateLimitEndpoint carries same settings as RateLimit but for endpoints.
type RateLimitEndpoint RateLimit
```

```go
// ReadableDuration is an alias maintained to be used in imports.
type ReadableDuration = time.ReadableDuration
```

```go
// RequestSizeLimit limits the maximum allowed size of the request body in bytes.
type RequestSizeLimit struct {
	// Enabled activates the Request Size Limit functionality.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Value is the maximum allowed size of the request body in bytes.
	Value int64 `bson:"value" json:"value"`
}
```

```go
// ResponsePlugin configures response plugins.
type ResponsePlugin struct {
	// Plugins configures custom plugins to be run on post stage.
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}
```

```go
// ScopeToPolicy contains a single scope to policy ID mapping.
type ScopeToPolicy struct {
	// Scope contains the scope name.
	Scope string `bson:"scope,omitempty" json:"scope,omitempty"`

	// PolicyID contains the Policy ID.
	PolicyID string `bson:"policyId,omitempty" json:"policyId,omitempty"`
}
```

```go
// Scopes holds the scope to policy mappings for a claim name.
type Scopes struct {
	// ClaimName contains the claim name.
	ClaimName string `bson:"claimName,omitempty" json:"claimName,omitempty"`

	// ScopeToPolicyMapping contains the mappings of scopes to policy IDs.
	ScopeToPolicyMapping []ScopeToPolicy `bson:"scopeToPolicyMapping,omitempty" json:"scopeToPolicyMapping,omitempty"`
}
```

```go
// SecurityScheme defines an Importer interface for security schemes.
type SecurityScheme interface {
	Import(nativeSS *openapi3.SecurityScheme, enable bool)
}
```

```go
// SecuritySchemes holds security scheme values, filled with Import().
type SecuritySchemes map[string]interface{}
```

```go
// Server contains the configuration that sets Tyk up to receive requests from the client applications.
type Server struct {
	// ListenPath is the base path on Tyk to which requests for this API should
	// be sent. Tyk listens for any requests coming into the host at this
	// path, on the port that Tyk is configured to run on and processes these
	// accordingly.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required

	// Authentication contains the configurations that manage how clients can authenticate with Tyk to access the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
	ClientCertificates *ClientCertificates `bson:"clientCertificates,omitempty" json:"clientCertificates,omitempty"`

	// GatewayTags contain segment tags to indicate which Gateways your upstream service is connected to (and hence where to deploy the API).
	GatewayTags *GatewayTags `bson:"gatewayTags,omitempty" json:"gatewayTags,omitempty"`

	// CustomDomain is the domain to bind this API to. This enforces domain matching for client requests.
	//
	// Tyk classic API definition: `domain`
	CustomDomain *Domain `bson:"customDomain,omitempty" json:"customDomain,omitempty"`

	// DetailedActivityLogs configures detailed analytics recording.
	DetailedActivityLogs *DetailedActivityLogs `bson:"detailedActivityLogs,omitempty" json:"detailedActivityLogs,omitempty"`

	// DetailedTracing enables OpenTelemetry's detailed tracing for this API.
	//
	// Tyk classic API definition: `detailed_tracing`
	DetailedTracing *DetailedTracing `bson:"detailedTracing,omitempty" json:"detailedTracing,omitempty"`

	// EventHandlers contains the configuration related to Tyk Events.
	//
	// Tyk classic API definition: `event_handlers`
	EventHandlers EventHandlers `bson:"eventHandlers,omitempty" json:"eventHandlers,omitempty"`

	// IPAccessControl configures IP access control for this API.
	//
	// Tyk classic API definition: `allowed_ips` and `blacklisted_ips`.
	IPAccessControl *IPAccessControl `bson:"ipAccessControl,omitempty" json:"ipAccessControl,omitempty"`

	// BatchProcessing contains configuration settings to enable or disable batch request support for the API.
	//
	// Tyk classic API definition: `enable_batch_request_support`.
	BatchProcessing *BatchProcessing `bson:"batchProcessing,omitempty" json:"batchProcessing,omitempty"`

	// Protocol configures the HTTP protocol used by the API.
	// Possible values are:
	// - "http": Standard HTTP/1.1 protocol
	// - "http2": HTTP/2 protocol with TLS
	// - "h2c": HTTP/2 protocol without TLS (cleartext).
	Protocol string `bson:"protocol,omitempty" json:"protocol,omitempty"`
	// Port Setting this value will change the port that Tyk listens on. Default: 8080.
	Port int `bson:"port,omitempty" json:"port,omitempty"`
}
```

```go
// ServiceDiscovery holds configuration required for service discovery.
type ServiceDiscovery struct {
	// Enabled activates Service Discovery.
	//
	// Tyk classic API definition: `service_discovery.use_discovery_service`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.
	// Tyk classic API definition: `service_discovery.query_endpoint`
	QueryEndpoint string `bson:"queryEndpoint,omitempty" json:"queryEndpoint,omitempty"`

	// DataPath is the namespace of the data path - where exactly in your service response the namespace can be found.
	// For example, if your service responds with:
	//
	// ```
	// {
	//  "action": "get",
	//  "node": {
	//    "key": "/services/single",
	//    "value": "http://httpbin.org:6000",
	//    "modifiedIndex": 6,
	//    "createdIndex": 6
	//  }
	// }
	// ```
	//
	// then your namespace would be `node.value`.
	//
	// Tyk classic API definition: `service_discovery.data_path`
	DataPath string `bson:"dataPath,omitempty" json:"dataPath,omitempty"`

	// UseNestedQuery enables the use of a combination of `dataPath` and `parentDataPath`.
	// It is necessary when the data lives within this string-encoded JSON object.
	//
	// ```
	// {
	//  "action": "get",
	//  "node": {
	//    "key": "/services/single",
	//    "value": "{"hostname": "http://httpbin.org", "port": "80"}",
	//    "modifiedIndex": 6,
	//    "createdIndex": 6
	//  }
	// }
	// ```
	//
	// Tyk classic API definition: `service_discovery.use_nested_query`
	UseNestedQuery bool `bson:"useNestedQuery,omitempty" json:"useNestedQuery,omitempty"`

	// ParentDataPath is the namespace of the where to find the nested
	// value if `useNestedQuery` is `true`. In the above example, it
	// would be `node.value`. You would change the `dataPath` setting
	// to be `hostname`, since this is where the host name data
	// resides in the JSON string. Tyk automatically assumes that
	// `dataPath` in this case is in a string-encoded JSON object and
	// will try to deserialize it.
	//
	// Tyk classic API definition: `service_discovery.parent_data_path`
	ParentDataPath string `bson:"parentDataPath,omitempty" json:"parentDataPath,omitempty"`

	// PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value
	// for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath` as
	// the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier
	// such as `/widgets/`). In the above example, the `portDataPath` would be `port`.
	//
	// Tyk classic API definition: `service_discovery.port_data_path`
	PortDataPath string `bson:"portDataPath,omitempty" json:"portDataPath,omitempty"`

	// UseTargetList should be set to `true` if you are using load balancing. Tyk will treat the data path as a list and
	// inject it into the target list of your API definition.
	//
	// Tyk classic API definition: `service_discovery.use_target_list`
	UseTargetList bool `bson:"useTargetList,omitempty" json:"useTargetList,omitempty"`

	// CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
	// Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that
	// failures are not recovered from quickly enough.
	//
	// Deprecated: The field is deprecated. Use `service_discovery` to configure service discovery cache options.
	//
	// Tyk classic API definition: `service_discovery.cache_timeout`
	CacheTimeout int64 `bson:"cacheTimeout,omitempty" json:"cacheTimeout,omitempty"`

	// Cache holds cache related flags.
	//
	// Tyk classic API definition:
	// - `service_discovery.cache_disabled`
	// - `service_discovery.cache_timeout`
	Cache *ServiceDiscoveryCache `bson:"cache,omitempty" json:"cache,omitempty"`

	// TargetPath is used to set a target path that will be appended to the
	// discovered endpoint, since many service discovery services only provide
	// host and port data. It is important to be able to target a specific
	// resource on that host. Setting this value will enable that.
	//
	// Tyk classic API definition: `service_discovery.target_path`
	TargetPath string `bson:"targetPath,omitempty" json:"targetPath,omitempty"`

	// EndpointReturnsList is set `true` when the response type is a list instead of an object.
	//
	// Tyk classic API definition: `service_discovery.endpoint_returns_list`
	EndpointReturnsList bool `bson:"endpointReturnsList,omitempty" json:"endpointReturnsList,omitempty"`
}
```

```go
// ServiceDiscoveryCache holds configuration for caching ServiceDiscovery data.
type ServiceDiscoveryCache struct {
	// Enabled turns service discovery cache on or off.
	//
	// Tyk classic API definition: `service_discovery.cache_disabled`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Timeout is the TTL for a cached object in seconds.
	//
	// Tyk classic API definition: `service_discovery.cache_timeout`
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`
}
```

```go
// Signature holds the configuration for signature validation.
type Signature struct {
	// Enabled activates signature validation.
	// Tyk classic API definition: `auth_configs[X].validate_signature`.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Algorithm is the signature method to use.
	// Tyk classic API definition: `auth_configs[X].signature.algorithm`.
	Algorithm string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	// Header is the name of the header to consume.
	// Tyk classic API definition: `auth_configs[X].signature.header`.
	Header string `bson:"header,omitempty" json:"header,omitempty"`
	// Query is the name of the query parameter to consume.
	// Tyk classic API definition: `auth_configs[X].signature.use_param/param_name`.
	Query AuthSource `bson:"query,omitempty" json:"query,omitempty"`
	// Secret is the signing secret used for signature validation.
	// Tyk classic API definition: `auth_configs[X].signature.secret`.
	Secret string `bson:"secret,omitempty" json:"secret,omitempty"`
	// AllowedClockSkew configures a grace period in seconds during which an expired token is still valid.
	// Tyk classic API definition: `auth_configs[X].signature.allowed_clock_skew`.
	AllowedClockSkew int64 `bson:"allowedClockSkew,omitempty" json:"allowedClockSkew,omitempty"`
	// ErrorCode configures the HTTP response code for a validation failure.
	// If unconfigured, a HTTP 401 Unauthorized status code will be emitted.
	// Tyk classic API definition: `auth_configs[X].signature.error_code`.
	ErrorCode int `bson:"errorCode,omitempty" json:"errorCode,omitempty"`
	// ErrorMessage configures the error message that is emitted on validation failure.
	// A default error message is emitted if unset.
	// Tyk classic API definition: `auth_configs[X].signature.error_message`.
	ErrorMessage string `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
}
```

```go
// State holds configuration for the status of the API within Tyk - if it is currently active and if it is exposed externally.
type State struct {
	// Active enables the API so that Tyk will listen for and process requests made to the listenPath.
	// Tyk classic API definition: `active`
	Active bool `bson:"active" json:"active"` // required
	// Internal makes the API accessible only internally.
	// Tyk classic API definition: `internal`
	Internal bool `bson:"internal,omitempty" json:"internal,omitempty"`
}
```

```go
// TLSTransport contains the configuration for TLS transport settings.
// This struct allows you to specify a custom proxy and set the minimum TLS versions and any SSL ciphers.
//
// Example:
//
//	{
//	  "proxy_url": "http(s)://proxy.url:1234",
//	  "minVersion": "1.0",
//	  "maxVersion": "1.0",
//	  "ciphers": [
//	    "TLS_RSA_WITH_AES_128_GCM_SHA256",
//	    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
//	  ],
//	  "insecureSkipVerify": true,
//	  "forceCommonNameCheck": false
//	}
//
// Tyk classic API definition: `proxy.transport`
type TLSTransport struct {
	// InsecureSkipVerify controls whether a client verifies the server's certificate chain and host name.
	// If InsecureSkipVerify is true, crypto/tls accepts any certificate presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used.
	// This should be used only for testing or in combination with VerifyConnection or VerifyPeerCertificate.
	//
	// Tyk classic API definition: `proxy.transport.ssl_insecure_skip_verify`
	InsecureSkipVerify bool `bson:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// Ciphers is a list of SSL ciphers to be used. If unset, the default ciphers will be used.
	//
	// Tyk classic API definition: `proxy.transport.ssl_ciphers`
	Ciphers []string `bson:"ciphers,omitempty" json:"ciphers,omitempty"`

	// MinVersion is the minimum SSL/TLS version that is acceptable.
	// Tyk classic API definition: `proxy.transport.ssl_min_version`
	MinVersion string `bson:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum SSL/TLS version that is acceptable.
	MaxVersion string `bson:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// ForceCommonNameCheck forces the validation of the hostname against the certificate Common Name.
	//
	// Tyk classic API definition: `proxy.transport.ssl_force_common_name_check`
	ForceCommonNameCheck bool `bson:"forceCommonNameCheck,omitempty" json:"forceCommonNameCheck,omitempty"`
}
```

```go
// Token holds the values related to authentication tokens.
type Token struct {
	// Enabled activates the token based authentication mode.
	//
	// Tyk classic API definition: `auth_configs["authToken"].use_standard_auth`
	Enabled bool `bson:"enabled" json:"enabled"` // required

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
```

```go
// TrackEndpoint configures Track or DoNotTrack behaviour for an endpoint.
// Tyk classic API definition: `version_data.versions..extended_paths.track_endpoints`, `version_data.versions..extended_paths.do_not_track_endpoints`.
type TrackEndpoint struct {
	// Enabled if set to true enables or disables tracking for an endpoint depending
	// if it's used in `trackEndpoint` or `doNotTrackEndpoint`.
	Enabled bool `bson:"enabled" json:"enabled"`
}
```

```go
// TrafficLogs holds configuration about API log analytics.
type TrafficLogs struct {
	// Enabled enables traffic log analytics for the API.
	// Tyk classic API definition: `do_not_track`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// TagHeaders is a string array of HTTP headers that can be extracted
	// and transformed into analytics tags (statistics aggregated by tag, per hour).
	TagHeaders []string `bson:"tagHeaders" json:"tagHeaders,omitempty"`
	// CustomRetentionPeriod configures a custom value for how long the analytics is retained for,
	// defaults to 100 years.
	CustomRetentionPeriod ReadableDuration `bson:"customRetentionPeriod,omitempty" json:"customRetentionPeriod,omitempty"`
	// Plugins configures custom plugins to allow for extensive modifications to analytics records
	// The plugins would be executed in the order of configuration in the list.
	Plugins CustomAnalyticsPlugins `bson:"plugins,omitempty" json:"plugins,omitempty"`
}
```

```go
// TransformBody holds configuration about request/response body transformations.
type TransformBody struct {
	// Enabled activates transform request/request body middleware.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Format of the request/response body, xml or json.
	Format apidef.RequestInputType `bson:"format" json:"format"`
	// Path file path for the template.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Body base64 encoded representation of the template.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
}
```

```go
// TransformHeaders holds configuration about request/response header transformations.
type TransformHeaders struct {
	// Enabled activates Header Transform for the given path and method.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Remove specifies header names to be removed from the request/response.
	Remove []string `bson:"remove,omitempty" json:"remove,omitempty"`
	// Add specifies headers to be added to the request/response.
	Add Headers `bson:"add,omitempty" json:"add,omitempty"`
}
```

```go
// TransformRequestMethod holds configuration for rewriting request methods.
type TransformRequestMethod struct {
	// Enabled activates Method Transform for the given path and method.
	Enabled bool `bson:"enabled" json:"enabled"`
	// ToMethod is the http method value to which the method of an incoming request will be transformed.
	ToMethod string `bson:"toMethod" json:"toMethod"`
}
```

```go
// TykExtensionConfigParams holds the essential configuration required for the Tyk Extension schema.
type TykExtensionConfigParams struct {
	// UpstreamURL configures the upstream URL.
	UpstreamURL string
	// ListenPath configures the listen path.
	ListenPath string
	// CustomDomain configures the domain name.
	CustomDomain string
	// ApiID is the API ID.
	ApiID string

	// Authentication is true if the API configures authentication.
	Authentication *bool
	// AllowList is true if the API configures an allow list.
	AllowList *bool
	// ValidateRequest is true if the API enables request validation.
	ValidateRequest *bool
	// MockResponse is true if a mocked response is configured.
	MockResponse *bool

	// pathItemHasParameters is set to true when parameters are defined the same level as of operations within path.
	pathItemHasParameters bool
}
```

```go
// URLRewrite configures URL rewriting.
// Tyk classic API definition: `version_data.versions[].extended_paths.url_rewrite`.
type URLRewrite struct {
	// Enabled activates URL rewriting if set to true.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Pattern is the regular expression against which the request URL is compared for the primary rewrite check.
	// If this matches the defined pattern, the primary URL rewrite is triggered.
	Pattern string `bson:"pattern,omitempty" json:"pattern,omitempty"`

	// RewriteTo specifies the URL to which the request shall be rewritten if the primary URL rewrite is triggered.
	RewriteTo string `bson:"rewriteTo,omitempty" json:"rewriteTo,omitempty"`

	// Triggers contain advanced additional triggers for the URL rewrite.
	// The triggers are processed only if the requested URL matches the pattern above.
	Triggers []*URLRewriteTrigger `bson:"triggers,omitempty" json:"triggers,omitempty"`
}
```

```go
// URLRewriteCondition defines the matching mode for an URL rewrite rules.
// - Value `any` means any of the defined trigger rules may match.
// - Value `all` means all the defined trigger rules must match.
type URLRewriteCondition string
```

```go
// URLRewriteInput defines the input for an URL rewrite rule.
// The following values are valid:
//
// - `url`, match pattern against URL
// - `query`, match pattern against named query parameter value
// - `path`, match pattern against named path parameter value
// - `header`, match pattern against named header value
// - `sessionMetadata`, match pattern against session metadata
// - `requestBody`, match pattern against request body
// - `requestContext`, match pattern against request context
//
// The default `url` is used as the input source.
type URLRewriteInput string
```

```go
// URLRewriteRule represents a rewrite matching rules.
type URLRewriteRule struct {
	// In specifies one of the valid inputs for URL rewriting.
	In URLRewriteInput `bson:"in" json:"in"`

	// Name is the index in the value declared inside `in`.
	//
	// Example: for `in=query`, `name=q`, the parameter `q` would
	// be read from the request query parameters.
	//
	// The value of name is unused when `in` is set to `requestBody`,
	// as the request body is a single value and not a set of values.
	Name string `bson:"name,omitempty" json:"name,omitempty"`

	// Pattern is the regular expression against which the `in` values are compared for this rule check.
	// If the value matches the defined `pattern`, the URL rewrite is triggered for this rule.
	Pattern string `bson:"pattern" json:"pattern"`

	// Negate is a boolean negation operator. Setting it to true inverts the matching behaviour
	// such that the rewrite will be triggered if the value does not match the `pattern` for this rule.
	Negate bool `bson:"negate,omitempty" json:"negate,omitempty"`
}
```

```go
// URLRewriteTrigger represents a set of matching rules for a rewrite.
type URLRewriteTrigger struct {
	// Condition indicates the logical combination that will be applied to the rules for an advanced trigger.
	Condition URLRewriteCondition `bson:"condition" json:"condition"`

	// Rules contain individual checks that are combined according to the
	// `condition` to determine if the URL rewrite will be triggered.
	// If empty, the trigger is ignored.
	Rules []*URLRewriteRule `bson:"rules,omitempty" json:"rules,omitempty"`

	// RewriteTo specifies the URL to which the request shall be rewritten
	// if indicated by the combination of `condition` and `rules`.
	RewriteTo string `bson:"rewriteTo" json:"rewriteTo"`
}
```

```go
// Upstream holds configuration for the upstream server to which Tyk should proxy requests.
type Upstream struct {
	// URL defines the upstream address (or target URL) to which requests should be proxied.
	// Tyk classic API definition: `proxy.target_url`
	URL string `bson:"url" json:"url"` // required

	// ServiceDiscovery contains the configuration related to Service Discovery.
	// Tyk classic API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`

	// UptimeTests contains the configuration related to uptime tests.
	UptimeTests *UptimeTests `bson:"uptimeTests,omitempty" json:"uptimeTests,omitempty"`

	// MutualTLS contains the configuration for establishing a mutual TLS connection between Tyk and the upstream server.
	MutualTLS *MutualTLS `bson:"mutualTLS,omitempty" json:"mutualTLS,omitempty"`

	// CertificatePinning contains the configuration related to certificate pinning.
	CertificatePinning *CertificatePinning `bson:"certificatePinning,omitempty" json:"certificatePinning,omitempty"`

	// RateLimit contains the configuration related to API level rate limit.
	RateLimit *RateLimit `bson:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Authentication contains the configuration related to upstream authentication.
	Authentication *UpstreamAuth `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// LoadBalancing contains configuration for load balancing between multiple upstream targets.
	LoadBalancing *LoadBalancing `bson:"loadBalancing,omitempty" json:"loadBalancing,omitempty"`

	// PreserveHostHeader contains the configuration for preserving the host header.
	PreserveHostHeader *PreserveHostHeader `bson:"preserveHostHeader,omitempty" json:"preserveHostHeader,omitempty"`
	// TLSTransport contains the configuration for TLS transport settings.
	// Tyk classic API definition: `proxy.transport`
	TLSTransport *TLSTransport `bson:"tlsTransport,omitempty" json:"tlsTransport,omitempty"`

	// Proxy contains the configuration for an internal proxy.
	// Tyk classic API definition: `proxy.proxy_url`
	Proxy *Proxy `bson:"proxy,omitempty" json:"proxy,omitempty"`
}
```

```go
// UpstreamAuth holds the configurations related to upstream API authentication.
type UpstreamAuth struct {
	// Enabled enables upstream API authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// BasicAuth holds the basic authentication configuration for upstream API authentication.
	BasicAuth *UpstreamBasicAuth `bson:"basicAuth,omitempty" json:"basicAuth,omitempty"`
	// OAuth contains the configuration for OAuth2 Client Credentials flow.
	OAuth *UpstreamOAuth `bson:"oauth,omitempty" json:"oauth,omitempty"`
	// RequestSigning holds the configuration for generating signed requests to an upstream API.
	RequestSigning *UpstreamRequestSigning `bson:"requestSigning,omitempty" json:"requestSigning,omitempty"`
}
```

```go
// UpstreamBasicAuth holds upstream basic authentication configuration.
type UpstreamBasicAuth struct {
	// Enabled enables upstream basic authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Header contains configurations for the header value.
	Header *AuthSource `bson:"header,omitempty" json:"header,omitempty"`
	// Username is the username to be used for upstream basic authentication.
	Username string `bson:"username" json:"username"`
	// Password is the password to be used for upstream basic authentication.
	Password string `bson:"password" json:"password"`
}
```

```go
// UpstreamOAuth holds the configuration for OAuth2 Client Credentials flow.
type UpstreamOAuth struct {
	// Enabled activates upstream OAuth2 authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// AllowedAuthorizeTypes specifies the allowed authorization types for upstream OAuth2 authentication.
	AllowedAuthorizeTypes []string `bson:"allowedAuthorizeTypes" json:"allowedAuthorizeTypes"`
	// ClientCredentials holds the configuration for OAuth2 Client Credentials flow.
	ClientCredentials *ClientCredentials `bson:"clientCredentials,omitempty" json:"clientCredentials,omitempty"`
	// PasswordAuthentication holds the configuration for upstream OAauth password authentication flow.
	PasswordAuthentication *PasswordAuthentication `bson:"password,omitempty" json:"password,omitempty"`
}
```

```go
// UpstreamRequestSigning represents configuration for generating signed requests to an upstream API.
type UpstreamRequestSigning struct {
	// Enabled determines if request signing is enabled or disabled.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// SignatureHeader specifies the HTTP header name for the signature.
	SignatureHeader string `bson:"signatureHeader,omitempty" json:"signatureHeader,omitempty"`
	// Algorithm represents the signing algorithm used (e.g., HMAC-SHA256).
	Algorithm string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	// KeyID identifies the key used for signing purposes.
	KeyID string `bson:"keyId,omitempty" json:"keyId,omitempty"`
	// Headers contains a list of headers included in the signature calculation.
	Headers []string `bson:"headers,omitempty" json:"headers,omitempty"`
	// Secret holds the secret used for signing when applicable.
	Secret string `bson:"secret,omitempty" json:"secret,omitempty"`
	// CertificateID specifies the certificate ID used in signing operations.
	CertificateID string `bson:"certificateId,omitempty" json:"certificateId,omitempty"`
}
```

```go
// UptimeTest configures an uptime test check.
type UptimeTest struct {
	// CheckURL is the URL for a request. If service discovery is in use,
	// the hostname will be resolved to a service host.
	//
	// Examples:
	//
	// - `http://database1.company.local`
	// - `https://webcluster.service/health`
	// - `127.0.0.1:6379` (for TCP checks).
	CheckURL string `bson:"url" json:"url"`

	// Protocol is the protocol for the request. Supported values are
	// `http` and `tcp`, depending on what kind of check is performed.
	Protocol string `bson:"protocol" json:"protocol"`

	// Timeout declares a timeout for the request. If the test exceeds
	// this timeout, the check fails.
	Timeout time.ReadableDuration `bson:"timeout" json:"timeout"`

	// Method allows you to customize the HTTP method for the test (`GET`, `POST`,...).
	Method string `bson:"method" json:"method"`

	// Headers contain any custom headers for the back end service.
	Headers map[string]string `bson:"headers" json:"headers,omitempty"`

	// Body is the body of the test request.
	Body string `bson:"body" json:"body"`

	// Commands are used for TCP checks.
	Commands []UptimeTestCommand `bson:"commands" json:"commands,omitempty"`

	// EnableProxyProtocol enables proxy protocol support when making request.
	// The back end service needs to support this.
	EnableProxyProtocol bool `bson:"enableProxyProtocol" json:"enableProxyProtocol"`
}
```

```go
// UptimeTestCommand handles additional checks for tcp connections.
type UptimeTestCommand struct {
	// Name can be either `send` or `expect`, designating if the
	// message should be sent, or read from the connection.
	Name string `bson:"name" json:"name"`

	// Message contains the payload to send or expect.
	Message string `bson:"message" json:"message"`
}
```

```go
// UptimeTests configures uptime tests.
type UptimeTests struct {
	// ServiceDiscovery contains the configuration related to test Service Discovery.
	// Tyk classic API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`

	// Tests contains individual connectivity tests defined for checking if a service is online.
	Tests []UptimeTest `bson:"tests,omitempty" json:"tests,omitempty"`

	// HostDownRetestPeriod is the time to wait until rechecking a failed test.
	// If undefined, the default testing interval (10s) is in use.
	// Setting this to a lower value would result in quicker recovery on failed checks.
	HostDownRetestPeriod time.ReadableDuration `bson:"hostDownRetestPeriod" json:"hostDownRetestPeriod"`

	// LogRetentionPeriod holds a time to live for the uptime test results.
	// If unset, a value of 100 years is the default.
	LogRetentionPeriod time.ReadableDuration `bson:"logRetentionPeriod" json:"logRetentionPeriod"`
}
```

```go
// ValidateRequest holds configuration required for validating requests.
type ValidateRequest struct {
	// Enabled is a boolean flag, if set to `true`, it enables request validation.
	Enabled bool `bson:"enabled" json:"enabled"`

	// ErrorResponseCode is the error code emitted when the request fails validation.
	// If unset or zero, the response will returned with http status 422 Unprocessable Entity.
	ErrorResponseCode int `bson:"errorResponseCode,omitempty" json:"errorResponseCode,omitempty"`
}
```

```go
// VersionToID contains a single mapping from a version name into an API ID.
type VersionToID struct {
	// Name contains the user chosen version name, e.g. `v1` or similar.
	Name string `bson:"name" json:"name"`
	// ID is the API ID for the version set in Name.
	ID string `bson:"id" json:"id"`
}
```

```go
// Versioning holds configuration for API versioning.
// Tyk classic API definition: `version_data`.
type Versioning struct {
	// Enabled is a boolean flag, if set to `true` it will enable versioning of the API.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name contains the name of the version as entered by the user ("v1" or similar).
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Default contains the default version name if a request is issued without a version.
	Default string `bson:"default" json:"default"` // required
	// Location contains versioning location information. It can be one of the following:
	//
	// - `header`,
	// - `url-param`,
	// - `url`.
	Location string `bson:"location" json:"location"` // required
	// Key contains the name of the key to check for versioning information.
	Key string `bson:"key" json:"key"` // required
	// Versions contains a list of versions that map to individual API IDs.
	Versions []VersionToID `bson:"versions" json:"versions"` // required
	// StripVersioningData is a boolean flag, if set to `true`, the API responses will be stripped of versioning data.
	StripVersioningData bool `bson:"stripVersioningData,omitempty" json:"stripVersioningData,omitempty"`
	// UrlVersioningPattern is a string that contains the pattern that if matched will remove the version from the URL.
	UrlVersioningPattern string `bson:"urlVersioningPattern,omitempty" json:"urlVersioningPattern,omitempty"`
	// FallbackToDefault controls the behaviour of Tyk when a versioned API is called with a nonexistent version name.
	// If set to `true` then the default API version will be invoked; if set to `false` Tyk will return an HTTP 404
	// `This API version does not seem to exist` error in this scenario.
	FallbackToDefault bool `bson:"fallbackToDefault,omitempty" json:"fallbackToDefault,omitempty"`
}
```

```go
// VirtualEndpoint contains virtual endpoint configuration.
type VirtualEndpoint struct {
	// Enabled activates virtual endpoint.
	Enabled bool `bson:"enabled" json:"enabled"` // required.
	// Name is the name of plugin function to be executed.
	// Deprecated: Use FunctionName instead.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// FunctionName is the name of plugin function to be executed.
	FunctionName string `bson:"functionName" json:"functionName"` // required.
	// Path is the path to JS file.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Body is the JS function to execute encoded in base64 format.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
	// ProxyOnError proxies if virtual endpoint errors out.
	ProxyOnError bool `bson:"proxyOnError,omitempty" json:"proxyOnError,omitempty"`
	// RequireSession if enabled passes session to virtual endpoint.
	RequireSession bool `bson:"requireSession,omitempty" json:"requireSession,omitempty"`
}
```

```go
// WebhookEvent stores the core information about a webhook event.
type WebhookEvent struct {
	// URL is the target URL for the webhook.
	URL string `json:"url" bson:"url"`
	// Method is the HTTP method for the webhook.
	Method string `json:"method" bson:"method"`
	// CoolDownPeriod defines cool-down for the event, so it does not trigger again.
	// It uses shorthand notation.
	// The value of CoolDownPeriod is a string that specifies the interval in a compact form,
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
	// An empty value is interpreted as "0s", implying no cool-down.
	// It's important to format the string correctly, as invalid formats will
	// be considered as 0s/empty.
	CoolDownPeriod ReadableDuration `json:"cooldownPeriod" bson:"cooldownPeriod"`
	// BodyTemplate is the template to be used for request payload.
	BodyTemplate string `json:"bodyTemplate,omitempty" bson:"bodyTemplate,omitempty"`
	// Headers are the list of request headers to be used.
	Headers Headers `json:"headers,omitempty" bson:"headers,omitempty"`
}
```

```go
// XTykAPIGateway contains custom Tyk API extensions for the OpenAPI definition.
// The values for the extensions are stored inside the OpenAPI document, under
// the key `x-tyk-api-gateway`.
type XTykAPIGateway struct {
	// Info contains the main metadata for the API definition.
	Info Info `bson:"info" json:"info"` // required
	// Upstream contains the configurations related to the upstream.
	Upstream Upstream `bson:"upstream" json:"upstream"` // required
	// Server contains the configurations related to the server.
	Server Server `bson:"server" json:"server"` // required
	// Middleware contains the configurations related to the Tyk middleware.
	Middleware *Middleware `bson:"middleware,omitempty" json:"middleware,omitempty"`
}
```

```go
// XTykStreaming represents the structure for Tyk streaming configurations.
type XTykStreaming struct {
	// Streams contains the configurations related to Tyk Streams.
	Streams map[string]interface{} `bson:"streams" json:"streams"` // required
}
```

## Consts

```go
// WebhookKind is an alias maintained to be used in imports.
const (
	WebhookKind = event.WebhookKind
	JSVMKind    = event.JSVMKind
)
```

```go
const (
	// ExtensionTykAPIGateway is the OAS schema key for the Tyk extension.
	ExtensionTykAPIGateway = "x-tyk-api-gateway"

	// ExtensionTykStreaming is the OAS schema key for the Tyk Streams extension.
	ExtensionTykStreaming = "x-tyk-streaming"

	// Main holds the default version value (empty).
	Main = ""

	// DefaultOpenAPI is the default open API version which is set to migrated APIs.
	DefaultOpenAPI = "3.0.6"
)
```

```go
// Enumerated constants for inputs and conditions.
const (
	InputQuery           URLRewriteInput = "query"
	InputPath            URLRewriteInput = "path"
	InputHeader          URLRewriteInput = "header"
	InputSessionMetadata URLRewriteInput = "sessionMetadata"
	InputRequestBody     URLRewriteInput = "requestBody"
	InputRequestContext  URLRewriteInput = "requestContext"

	ConditionAll URLRewriteCondition = "all"
	ConditionAny URLRewriteCondition = "any"
)
```

## Vars

```go
// ShouldOmit is a compatibility alias. It may be removed in the future.
var ShouldOmit = internalreflect.IsEmpty
```

```go
var (
	// URLRewriteConditions contains all valid URL rewrite condition values.
	URLRewriteConditions = []URLRewriteCondition{
		ConditionAll,
		ConditionAny,
	}

	// URLRewriteInputs contains all valid URL rewrite input values.
	URLRewriteInputs = []URLRewriteInput{
		InputQuery,
		InputPath,
		InputHeader,
		InputSessionMetadata,
		InputRequestBody,
		InputRequestContext,
	}
)
```

## Function symbols

- `func ExampleExtractor (schema *openapi3.SchemaRef) interface{}`
- `func GetOASSchema (version string) ([]byte, error)`
- `func GetTykExtensionConfigParams (r *http.Request) *TykExtensionConfigParams`
- `func GetValidationOptionsFromConfig (oasConfig config.OASConfig) []openapi3.ValidationOption`
- `func MigrateAndFillOAS (api *apidef.APIDefinition) (APIDef, []APIDef, error)`
- `func NewHeaders (in map[string]string) Headers`
- `func RetainOldServerURL (oldServers,newServers openapi3.Servers) openapi3.Servers`
- `func ValidateOASObject (documentBody []byte, oasVersion string) error`
- `func ValidateOASTemplate (documentBody []byte, oasVersion string) error`
- `func (*CustomKeyLifetime) ExtractTo (api *apidef.APIDefinition)`
- `func (*CustomKeyLifetime) Fill (api apidef.APIDefinition)`
- `func (*EventHandler) GetJSVMEventHandlerConf () apidef.JSVMEventHandlerConf`
- `func (*EventHandler) GetWebhookConf () apidef.WebHookHandlerConf`
- `func (*EventHandler) UnmarshalJSON (in []byte) error`
- `func (*OAS) AddServers (apiURLs ...string)`
- `func (*OAS) BuildDefaultTykExtension (overRideValues TykExtensionConfigParams, isImport bool) error`
- `func (*OAS) Clone () (*OAS, error)`
- `func (*OAS) GetTykExtension () *XTykAPIGateway`
- `func (*OAS) GetTykMiddleware () *Middleware`
- `func (*OAS) GetTykStreamingExtension () *XTykStreaming`
- `func (*OAS) RemoveTykExtension ()`
- `func (*OAS) RemoveTykStreamingExtension ()`
- `func (*OAS) ReplaceServers (apiURLs,oldAPIURLs []string)`
- `func (*OAS) SetTykExtension (xTykAPIGateway *XTykAPIGateway)`
- `func (*OAS) SetTykStreamingExtension (xTykStreaming *XTykStreaming)`
- `func (*OAS) UpdateServers (apiURL,oldAPIURL string)`
- `func (*OldOAS) ConvertToNewerOAS () (*OAS, error)`
- `func (*ServiceDiscovery) CacheOptions () (int64, bool)`
- `func (*URLRewrite) Sort ()`
- `func (*UptimeTest) AddCommand (name,message string)`
- `func (EventHandler) MarshalJSON () ([]byte, error)`
- `func (Headers) Map () map[string]string`
- `func (SecuritySchemes) GetBaseIdentityProvider () apidef.AuthTypeEnum`
- `func (SecuritySchemes) Import (name string, nativeSS *openapi3.SecurityScheme, enable bool) error`
- `func (URLRewriteInput) Err () error`
- `func (URLRewriteInput) Index () int`
- `func (URLRewriteInput) Valid () bool`

### ExampleExtractor

ExampleExtractor returns an example payload according to the openapi3.SchemaRef object.

```go
func ExampleExtractor(schema *openapi3.SchemaRef) interface{}
```

### GetOASSchema

GetOASSchema returns an oas schema for a particular version.

```go
func GetOASSchema(version string) ([]byte, error)
```

### GetTykExtensionConfigParams

GetTykExtensionConfigParams extracts a *TykExtensionConfigParams from a *http.Request.

```go
func GetTykExtensionConfigParams(r *http.Request) *TykExtensionConfigParams
```

### GetValidationOptionsFromConfig

GetValidationOptionsFromConfig retrieves validation options based on the configuration settings.

```go
func GetValidationOptionsFromConfig(oasConfig config.OASConfig) []openapi3.ValidationOption
```

### MigrateAndFillOAS

MigrateAndFillOAS migrates classic APIs to OAS-compatible forms. Then, it fills an OAS with it. To be able to make it a valid OAS, it adds some required fields. It returns base API and its versions if any.

```go
func MigrateAndFillOAS(api *apidef.APIDefinition) (APIDef, []APIDef, error)
```

### NewHeaders

NewHeaders creates Headers from in map.

```go
func NewHeaders(in map[string]string) Headers
```

### RetainOldServerURL

RetainOldServerURL retains the first entry from old servers provided tyk adds a server URL to the start of oas.Servers to add the gw URL RetainOldServerURL can be used when API def is patched.

```go
func RetainOldServerURL(oldServers, newServers openapi3.Servers) openapi3.Servers
```

### ValidateOASObject

ValidateOASObject validates an OAS document against a particular OAS version.

```go
func ValidateOASObject(documentBody []byte, oasVersion string) error
```

### ValidateOASTemplate

ValidateOASTemplate checks a Tyk OAS API template for necessary fields, acknowledging that some standard Tyk OAS API fields are optional in templates.

```go
func ValidateOASTemplate(documentBody []byte, oasVersion string) error
```

### ExtractTo

ExtractTo extracts *Authentication into *apidef.APIDefinition.

```go
func (*CustomKeyLifetime) ExtractTo(api *apidef.APIDefinition)
```

### Fill

Fill fills *CustomKeyLifetime from apidef.APIDefinition.

```go
func (*CustomKeyLifetime) Fill(api apidef.APIDefinition)
```

### GetJSVMEventHandlerConf

GetJSVMEventHandlerConf generates the JavaScript VM event handler configuration using the current EventHandler instance.

```go
func (*EventHandler) GetJSVMEventHandlerConf() apidef.JSVMEventHandlerConf
```

### GetWebhookConf

GetWebhookConf converts EventHandler.WebhookEvent apidef.WebHookHandlerConf.

```go
func (*EventHandler) GetWebhookConf() apidef.WebHookHandlerConf
```

### UnmarshalJSON

UnmarshalJSON unmarshal EventHandler as per Tyk OAS API definition contract.

```go
func (*EventHandler) UnmarshalJSON(in []byte) error
```

### AddServers

AddServers adds a server into the servers definition if not already present.

```go
func (*OAS) AddServers(apiURLs ...string)
```

### BuildDefaultTykExtension

BuildDefaultTykExtension builds a default tyk extension in *OAS based on function arguments.

```go
func (*OAS) BuildDefaultTykExtension(overRideValues TykExtensionConfigParams, isImport bool) error
```

### Clone

Clone creates a deep copy of the OAS object and returns a new instance.

```go
func (*OAS) Clone() (*OAS, error)
```

### GetTykExtension

GetTykExtension returns our OAS schema extension from inside *OAS.

```go
func (*OAS) GetTykExtension() *XTykAPIGateway
```

### GetTykMiddleware

GetTykMiddleware returns middleware section from XTykAPIGateway.

```go
func (*OAS) GetTykMiddleware() *Middleware
```

### RemoveTykExtension

RemoveTykExtension clears the Tyk extensions from *OAS.

```go
func (*OAS) RemoveTykExtension()
```

### ReplaceServers

ReplaceServers replaces OAS servers entry having oldAPIURLs with new apiURLs .

```go
func (*OAS) ReplaceServers(apiURLs, oldAPIURLs []string)
```

### SetTykExtension

SetTykExtension populates our OAS schema extension inside *OAS.

```go
func (*OAS) SetTykExtension(xTykAPIGateway *XTykAPIGateway)
```

### UpdateServers

UpdateServers sets or updates the first servers URL if it matches oldAPIURL.

```go
func (*OAS) UpdateServers(apiURL, oldAPIURL string)
```

### ConvertToNewerOAS

ConvertToNewerOAS converts a deprecated OldOAS object to the newer OAS representation.

```go
func (*OldOAS) ConvertToNewerOAS() (*OAS, error)
```

### CacheOptions

CacheOptions returns the timeout value in effect and a bool if cache is enabled.

```go
func (*ServiceDiscovery) CacheOptions() (int64, bool)
```

### Sort

Sort reorders the internal trigger rules.

```go
func (*URLRewrite) Sort()
```

### AddCommand

AddCommand will append a new command to the test.

```go
func (*UptimeTest) AddCommand(name, message string)
```

### MarshalJSON

MarshalJSON marshals EventHandler as per Tyk OAS API definition contract.

```go
func (EventHandler) MarshalJSON() ([]byte, error)
```

### Map

Map transforms Headers into a map.

```go
func (Headers) Map() map[string]string
```

### GetBaseIdentityProvider

GetBaseIdentityProvider returns the identity provider by precedence from SecuritySchemes.

```go
func (SecuritySchemes) GetBaseIdentityProvider() apidef.AuthTypeEnum
```

### Import

Import takes the openapi3.SecurityScheme as argument and applies it to the receiver. The SecuritySchemes receiver is a map, so modification of the receiver is enabled, regardless of the fact that the receiver isn't a pointer type. The map is a pointer type itself.

```go
func (SecuritySchemes) Import(name string, nativeSS *openapi3.SecurityScheme, enable bool) error
```

### Err

Err returns an error if the type value is invalid, nil otherwise.

```go
func (URLRewriteInput) Err() error
```

### Index

Index returns the cardinal order for the value. Used for sorting.

```go
func (URLRewriteInput) Index() int
```

### Valid

Valid returns true if the type value matches valid values, false otherwise.

```go
func (URLRewriteInput) Valid() bool
```

### GetTykStreamingExtension

```go
func (*OAS) GetTykStreamingExtension() *XTykStreaming
```

### RemoveTykStreamingExtension

```go
func (*OAS) RemoveTykStreamingExtension()
```

### SetTykStreamingExtension

```go
func (*OAS) SetTykStreamingExtension(xTykStreaming *XTykStreaming)
```
