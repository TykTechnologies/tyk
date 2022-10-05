
## TYK OAS API Object

### **x-tyk-gateway**

**Field: `info`**

**Type: [Info](#info)**

Info contains the main metadata about the API definition.

**Field: `upstream`**

**Type: [Upstream](#upstream)**

Upstream contains the configurations related to the upstream.

**Field: `server`**

**Type: [Server](#server)**

Server contains the configurations related to the server.

**Field: `middleware`**

**Type: [Middleware](#middleware)**

Middleware contains the configurations related to the proxy middleware.


### **Info**

**Field: `id`**

**Type: `string`**

ID is the unique ID of the API.

Tyk native API definition: `api_id`.

**Field: `dbId`**

**Type: `object`**

DBID is the unique database ID of the API.

Tyk native API definition: `id`.

**Field: `orgId`**

**Type: `string`**

OrgID is the ID of the organisation which the API belongs to.

Tyk native API definition: `org_id`.

**Field: `name`**

**Type: `string`**

Name is the name of the API.

Tyk native API definition: `name`.

**Field: `expiration`**

**Type: `string`**

Expiration date.

**Field: `state`**

**Type: [State](#state)**

State holds configuration about API definition states (active, internal).

**Field: `versioning`**

**Type: [Versioning](#versioning)**

Versioning holds configuration for API versioning.


### **State**

**Field: `active`**

**Type: `boolean`**

Active enables the API.

Tyk native API definition: `active`.

**Field: `internal`**

**Type: `boolean`**

Internal makes the API accessible only internally.

Tyk native API definition: `internal`.


### **Versioning**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag, if set to `true` it will enable versioning of an API.

**Field: `name`**

**Type: `string`**

Name contains the name of the version as entered by the user ("v1" or similar).

**Field: `default`**

**Type: `string`**

Default contains the default version name if a request is issued without a version.

**Field: `location`**

**Type: `string`**

Location contains versioning location information. It can be one of the following:

- `header`,
- `url-param`,
- `url`.

**Field: `key`**

**Type: `string`**

Key contains the name of the key to check for versioning information.

**Field: `versions`**

**Type: `[]`[VersionToID](#versiontoid)**

Versions contains a list of versions that map to individual API IDs.

**Field: `stripVersioningData`**

**Type: `boolean`**

StripVersioningData is a boolean flag, if set to `true`, the API responses will be stripped of versioning data.


### **VersionToID**

**Field: `name`**

**Type: `string`**

Name contains the user chosen version name, e.g. `v1` or similar.

**Field: `id`**

**Type: `string`**

ID is the API ID for the version set in Name.


### **Upstream**

**Field: `url`**

**Type: `string`**

URL defines the target URL that the request should be proxied to.

Tyk native API definition: `proxy.target_url`.

**Field: `serviceDiscovery`**

**Type: [ServiceDiscovery](#servicediscovery)**

ServiceDiscovery contains the configuration related to Service Discovery.

Tyk native API definition: `proxy.service_discovery`.

**Field: `test`**

**Type: [Test](#test)**

Test contains the configuration related to uptime tests.

**Field: `mutualTLS`**

**Type: [MutualTLS](#mutualtls)**

MutualTLS contains the configuration related to upstream mutual TLS.

**Field: `certificatePinning`**

**Type: [CertificatePinning](#certificatepinning)**

CertificatePinning contains the configuration related to certificate pinning.


### **ServiceDiscovery**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables Service Discovery.

Tyk native API definition: `service_discovery.use_discovery_service`.

**Field: `queryEndpoint`**

**Type: `string`**

QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.

Tyk native API definition: `service_discovery.query_endpoint`.

**Field: `dataPath`**

**Type: `string`**

DataPath is the namespace of the data path - where exactly in your service response the namespace can be found.
For example, if your service responds with:


```
{
 "action": "get",
 "node": {
   "key": "/services/single",
   "value": "http://httpbin.org:6000",
   "modifiedIndex": 6,
   "createdIndex": 6
 }
}

```

then your namespace would be `node.value`.

Tyk native API definition: `service_discovery.data_path`.

**Field: `useNestedQuery`**

**Type: `boolean`**

UseNestedQuery enables using a combination of `dataPath` and `parentDataPath`.
It is necessary when the data lives within this string-encoded JSON object.


```
{
 "action": "get",
 "node": {
   "key": "/services/single",
   "value": "{"hostname": "http://httpbin.org", "port": "80"}",
   "modifiedIndex": 6,
   "createdIndex": 6
 }
}

```


Tyk native API definition: `service_discovery.use_nested_query`.

**Field: `parentDataPath`**

**Type: `string`**

ParentDataPath is the namespace of the where to find the nested value, if `useNestedQuery` is `true`. In the above example, it would be `node.value`. You would change the `dataPath` setting to be `hostname`, since this is where the host name data resides in the JSON string. Tyk automatically assumes that `dataPath` in this case is in a string-encoded JSON object and will try to deserialize it.

Tyk native API definition: `service_discovery.parent_data_path`.

**Field: `portDataPath`**

**Type: `string`**

PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath` as the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier such as `/widgets/`). In the above example, the `portDataPath` would be `port`.

Tyk native API definition: `service_discovery.port_data_path`.

**Field: `useTargetList`**

**Type: `boolean`**

UseTargetList should be set to `true`, if you are using load balancing. Tyk will treat the data path as a list and inject it into the target list of your API definition.

Tyk native API definition: `service_discovery.use_target_list`.

**Field: `cacheTimeout`**

**Type: `int`**

CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that failures are not recovered from quickly enough.

Tyk native API definition: `service_discovery.cache_timeout`.

**Field: `targetPath`**

**Type: `string`**

TargetPath is to set a target path to append to the discovered endpoint, since many SD services only provide host and port data. It is important to be able to target a specific resource on that host.
Setting this value will enable that.

Tyk native API definition: `service_discovery.target_path`.

**Field: `endpointReturnsList`**

**Type: `boolean`**

EndpointReturnsList is set `true` when the response type is a list instead of an object.

Tyk native API definition: `service_discovery.endpoint_returns_list`.


### **Test**

**Field: `serviceDiscovery`**

**Type: [ServiceDiscovery](#servicediscovery)**

ServiceDiscovery contains the configuration related to test Service Discovery.

Tyk native API definition: `proxy.service_discovery`.


### **MutualTLS**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables/disables upstream mutual TLS auth for the API.

Tyk native API definition: `upstream_certificates_disabled`.

**Field: `domainToCertificateMapping`**

**Type: `[]`[DomainToCertificate](#domaintocertificate)**

DomainToCertificates maintains the mapping of domain to certificate.

Tyk native API definition: `upstream_certificates`.


### **DomainToCertificate**

**Field: `domain`**

**Type: `string`**

Domain contains the domain name.

**Field: `certificate`**

**Type: `string`**

Certificate contains the certificate mapped to the domain.


### **CertificatePinning**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag, if set to `true`, it enables certificate pinning for the API.

Tyk native API definition: `certificate_pinning_disabled`.

**Field: `domainToPublicKeysMapping`**

**Type: `[]`[PinnedPublicKey](#pinnedpublickey)**

DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.

Tyk native API definition: `pinned_public_keys`.


### **PinnedPublicKey**

**Field: `domain`**

**Type: `string`**

Domain contains the domain name.

**Field: `publicKeys`**

**Type: `[]string`**

PublicKeys contains a list of the public keys pinned to the domain name.


### **Server**

**Field: `listenPath`**

**Type: [ListenPath](#listenpath)**

ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on, that match this path will have the rules defined in the API definition applied.

**Field: `slug`**

**Type: `string`**

Slug is the Tyk Cloud equivalent of listen path.

Tyk native API definition: `slug`.

**Field: `authentication`**

**Type: [Authentication](#authentication)**

Authentication contains the configurations related to authentication to the API.

**Field: `clientCertificates`**

**Type: [ClientCertificates](#clientcertificates)**

ClientCertificates contains the configurations related to static mTLS.

**Field: `gatewayTags`**

**Type: [GatewayTags](#gatewaytags)**

GatewayTags contains segment tags to configure which GWs your APIs connect to.

**Field: `customDomain`**

**Type: [Domain](#domain)**

CustomDomain is the domain to bind this API to.

Tyk native API definition: `domain`.


### **ListenPath**

**Field: `value`**

**Type: `string`**

Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.

Tyk native API definition: `proxy.listen_path`.

**Field: `strip`**

**Type: `boolean`**

Strip removes the inbound listen path in the outgoing request. e.g. `http://acme.com/httpbin/get` where `httpbin`is the listen path. The `httpbin` listen path which is used to identify the API loaded in Tyk is removed, and the outbound request would be `http://httpbin.org/get`.

Tyk native API definition: `proxy.strip_listen_path`.


### **Authentication**

**Field: `enabled`**

**Type: `boolean`**

Enabled makes the API protected when one of the authentication modes is enabled.

Tyk native API definition: `!use_keyless`.

**Field: `stripAuthorizationData`**

**Type: `boolean`**

StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not leaked to the upstream.

Tyk native API definition: `strip_auth_data`.

**Field: `baseIdentityProvider`**

**Type: `object`**

BaseIdentityProvider enables multi authentication mechanism and provides the session object that determines rate limits, ACL rules and quotas.
It should be set to one of the following:

- `auth_token`,
- `hmac_key`,
- `basic_auth_user`,
- `jwt_claim`,
- `oidc_user`,
- `oauth_key`.


Tyk native API definition: `base_identity_provided_by`.

**Field: `hmac`**

**Type: [HMAC](#hmac)**

HMAC contains the configurations related to HMAC authentication mode.

Tyk native API definition: `auth_configs["hmac"]`.

**Field: `oidc`**

**Type: [OIDC](#oidc)**

OIDC contains the configurations related to OIDC authentication mode.

Tyk native API definition: `auth_configs["oidc"]`.

**Field: `goPlugin`**

**Type: [GoPlugin](#goplugin)**

GoPlugin contains the configurations related to GoPlugin authentication mode.

**Field: `customPlugin`**

**Type: [CustomPlugin](#customplugin)**

CustomPlugin contains the configurations related to CustomPlugin authentication mode.

Tyk native API definition: `auth_configs["coprocess"]`.

**Field: `securitySchemes`**

**Type: `map[string]any`**

SecuritySchemes contains security schemes definitions.


### **HMAC**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the HMAC authentication mode.

Tyk native API definition: `enable_signature_checking`.

**Field: `header`**

**Type: [AuthSource](#authsource)**

Header contains configurations for the header value auth source, it is enabled by default.

Tyk native API definition: `auth_configs[x].header`.

**Field: `cookie`**

**Type: [AuthSource](#authsource)**

Cookie contains configurations for the cookie value auth source.

Tyk native API definition: `auth_configs[x].cookie`.

**Field: `query`**

**Type: [AuthSource](#authsource)**

Query contains configurations for the query parameters auth source.

Tyk native API definition: `auth_configs[x].query`.

**Field: `allowedAlgorithms`**

**Type: `[]string`**

AllowedAlgorithms is the array of HMAC algorithms which are allowed. Tyk supports the following HMAC algorithms:

- `hmac-sha1`
- `hmac-sha256`
- `hmac-sha384`
- `hmac-sha512`

and reads the value from algorithm header.

Tyk native API definition: `hmac_allowed_algorithms`.

**Field: `allowedClockSkew`**

**Type: `double`**

AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
The default value is `0`, which deactivates clock skew checks.

Tyk native API definition: `hmac_allowed_clock_skew`.


### **AuthSources**

**Field: `header`**

**Type: [AuthSource](#authsource)**

Header contains configurations for the header value auth source, it is enabled by default.

Tyk native API definition: `auth_configs[x].header`.

**Field: `cookie`**

**Type: [AuthSource](#authsource)**

Cookie contains configurations for the cookie value auth source.

Tyk native API definition: `auth_configs[x].cookie`.

**Field: `query`**

**Type: [AuthSource](#authsource)**

Query contains configurations for the query parameters auth source.

Tyk native API definition: `auth_configs[x].query`.


### **AuthSource**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the auth source.

Tyk native API definition: `auth_configs[X].use_param/use_cookie`.

**Field: `name`**

**Type: `string`**

Name is the name of the auth source.

Tyk native API definition: `auth_configs[X].param_name/cookie_name`.


### **OIDC**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the OIDC authentication mode.

Tyk native API definition: `use_openid`.

**Field: `header`**

**Type: [AuthSource](#authsource)**

Header contains configurations for the header value auth source, it is enabled by default.

Tyk native API definition: `auth_configs[x].header`.

**Field: `cookie`**

**Type: [AuthSource](#authsource)**

Cookie contains configurations for the cookie value auth source.

Tyk native API definition: `auth_configs[x].cookie`.

**Field: `query`**

**Type: [AuthSource](#authsource)**

Query contains configurations for the query parameters auth source.

Tyk native API definition: `auth_configs[x].query`.

**Field: `segregateByClientId`**

**Type: `boolean`**

SegregateByClientId is a boolean flag. If set to `true, the policies will be applied to a combination of Client ID and User ID.

Tyk native API definition: `openid_options.segregate_by_client`.

**Field: `providers`**

**Type: `[]`[Provider](#provider)**

Providers contains a list of authorised providers and their Client IDs, and matched policies.

Tyk native API definition: `openid_options.providers`.

**Field: `scopes`**

**Type: [Scopes](#scopes)**

Scopes contains the defined scope claims.


### **Provider**

**Field: `issuer`**

**Type: `string`**

Issuer contains a validation value for the issuer claim, usually a domain name e.g. `accounts.google.com` or similar.

**Field: `clientToPolicyMapping`**

**Type: `[]`[ClientToPolicy](#clienttopolicy)**

ClientToPolicyMapping contains mappings of Client IDs to Policy IDs.


### **ClientToPolicy**

**Field: `clientId`**

**Type: `string`**

ClientID contains a Client ID.

**Field: `policyId`**

**Type: `string`**

PolicyID contains a Policy ID.


### **Scopes**

**Field: `claimName`**

**Type: `string`**

ClaimName contains the claim name.

**Field: `scopeToPolicyMapping`**

**Type: `[]`[ScopeToPolicy](#scopetopolicy)**

ScopeToPolicyMapping contains the mappings of scopes to policy IDs.


### **ScopeToPolicy**

**Field: `scope`**

**Type: `string`**

Scope contains the scope name.

**Field: `policyId`**

**Type: `string`**

PolicyID contains the Policy ID.


### **GoPlugin**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the GoPlugin authentication mode.

Tyk native API definition: `use_go_plugin_auth`.


### **CustomPlugin**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the CustomPlugin authentication mode.

Tyk native API definition: `enable_coprocess_auth`.

**Field: `header`**

**Type: [AuthSource](#authsource)**

Header contains configurations for the header value auth source, it is enabled by default.

Tyk native API definition: `auth_configs[x].header`.

**Field: `cookie`**

**Type: [AuthSource](#authsource)**

Cookie contains configurations for the cookie value auth source.

Tyk native API definition: `auth_configs[x].cookie`.

**Field: `query`**

**Type: [AuthSource](#authsource)**

Query contains configurations for the query parameters auth source.

Tyk native API definition: `auth_configs[x].query`.


### **ClientCertificates**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables static mTLS for the API.

**Field: `allowlist`**

**Type: `[]string`**

Allowlist is the list of client certificates which are allowed.


### **GatewayTags**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables use of segment tags.

**Field: `tags`**

**Type: `[]string`**

Tags is a list of segment tags


### **Domain**

**Field: `enabled`**

**Type: `boolean`**

Enabled allow/disallow the usage of the domain.

**Field: `name`**

**Type: `string`**

Name is the name of the domain.


### **Middleware**

**Field: `global`**

**Type: [Global](#global)**

Global contains the configurations related to the global middleware.

**Field: `operations`**

**Type: `map[string]`[Operation](#operation)**

Operations configuration.


### **Global**

**Field: `cors`**

**Type: [CORS](#cors)**

CORS contains the configuration related to cross origin resource sharing.

Tyk native API definition: `CORS`.

**Field: `cache`**

**Type: [Cache](#cache)**

Cache contains the configurations related to caching.

Tyk native API definition: `cache_options`.


### **CORS**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag, if set to `true`, this option enables CORS processing.

Tyk native API definition: `CORS.enable`.

**Field: `maxAge`**

**Type: `int`**

MaxAge indicates how long (in seconds) the results of a preflight request can be cached. The default is 0 which stands for no max age.

Tyk native API definition: `CORS.max_age`.

**Field: `allowCredentials`**

**Type: `boolean`**

AllowCredentials indicates whether the request can include user credentials like cookies, HTTP authentication or client side SSL certificates.

Tyk native API definition: `CORS.allow_credentials`.

**Field: `exposedHeaders`**

**Type: `[]string`**

ExposedHeaders indicates which headers are safe to expose to the API of a CORS API specification.

Tyk native API definition: `CORS.exposed_headers`.

**Field: `allowedHeaders`**

**Type: `[]string`**

AllowedHeaders holds a list of non simple headers the client is allowed to use with cross-domain requests.

Tyk native API definition: `CORS.allowed_headers`.

**Field: `optionsPassthrough`**

**Type: `boolean`**

OptionsPassthrough is a boolean flag. If set to `true`, it will proxy the CORS OPTIONS pre-flight request directly to upstream, without authentication and any CORS checks. This means that pre-flight requests generated by web-clients such as SwaggerUI or the Tyk Portal documentation system will be able to test the API using trial keys.
If your service handles CORS natively, then enable this option.

Tyk native API definition: `CORS.options_passthrough`.

**Field: `debug`**

**Type: `boolean`**

Debug is a boolean flag, If set to `true`, this option produces log files for the CORS middleware.

Tyk native API definition: `CORS.debug`.

**Field: `allowedOrigins`**

**Type: `[]string`**

AllowedOrigins holds a list of origin domains to allow access from. Wildcards are also supported, e.g. `http://*.foo.com`.

Tyk native API definition: `CORS.allowed_origins`.

**Field: `allowedMethods`**

**Type: `[]string`**

AllowedMethods holds a list of methods to allow access via.

Tyk native API definition: `CORS.allowed_methods`.


### **Cache**

**Field: `enabled`**

**Type: `boolean`**

Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis by explicitly setting the endpoint cache middleware.

Tyk native API definition: `cache_options.enable_cache`.

**Field: `timeout`**

**Type: `int`**

Timeout is the TTL for a cached object in seconds.

Tyk native API definition: `cache_options.cache_timeout`.

**Field: `cacheAllSafeRequests`**

**Type: `boolean`**

CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions, applies across versions.

Tyk native API definition: `cache_options.cache_all_safe_requests`.

**Field: `cacheResponseCodes`**

**Type: `[]int`**

CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.

Tyk native API definition: `cache_options.cache_response_codes`.

**Field: `cacheByHeaders`**

**Type: `[]string`**

CacheByHeaders allows header values to be used as part of the cache key.

Tyk native API definition: `cache_options.cache_by_headers`.

**Field: `enableUpstreamCacheControl`**

**Type: `boolean`**

EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.

Tyk native API definition: `cache_options.enable_upstream_cache_control`.

**Field: `controlTTLHeaderName`**

**Type: `string`**

ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.

Tyk native API definition: `cache_options.cache_control_ttl_header`.


### **Operation**

**Field: `allow`**

**Type: [Allowance](#allowance)**

Allow request by allowance.

**Field: `block`**

**Type: [Allowance](#allowance)**

Block request by allowance.

**Field: `ignoreAuthentication`**

**Type: [Allowance](#allowance)**

IgnoreAuthentication ignores authentication on request by allowance.

**Field: `transformRequestMethod`**

**Type: [TransformRequestMethod](#transformrequestmethod)**

TransformRequestMethod allows you to transform the method of a request.

**Field: `transformRequestBody`**

**Type: [TransformRequestBody](#transformrequestbody)**

TransformRequestBody allows you to transform request body.
When both `path` and `body` are provided, body would take precedence.

**Field: `cache`**

**Type: [CachePlugin](#cacheplugin)**

Cache contains the caching plugin configuration.

**Field: `enforceTimeout`**

**Type: [EnforceTimeout](#enforcetimeout)**

EnforceTimeout contains the request timeout configuration.

**Field: `validateRequest`**

**Type: [ValidateRequest](#validaterequest)**

ValidateRequest contains the request validation configuration.

**Field: `mockResponse`**

**Type: [MockResponse](#mockresponse)**

MockResponse contains the mock response configuration.


### **Allowance**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag, if set to `true`, then individual allowances (allow, block, ignore) will be enforced.

**Field: `ignoreCase`**

**Type: `boolean`**

IgnoreCase is a boolean flag, If set to `true`, checks for requests allowance will be case insensitive.


### **TransformRequestMethod**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables Method Transform for the given path and method.

**Field: `toMethod`**

**Type: `string`**

ToMethod is the http method value to which the method of an incoming request will be transformed.


### **TransformRequestBody**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables transform request body middleware.

**Field: `format`**

**Type: `object`**

Format of the request body, xml or json.

**Field: `path`**

**Type: `string`**

Path file path for the template.

**Field: `body`**

**Type: `string`**

Body base64 encoded representation of the template.


### **CachePlugin**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag. If set to `true`, the advanced caching plugin will be enabled.

**Field: `cacheByRegex`**

**Type: `string`**

CacheByRegex defines a regular expression used against the request body to produce a cache key.
Example value: `\"id\":[^,]*` (quoted json value).

**Field: `cacheResponseCodes`**

**Type: `[]int`**

CacheResponseCodes contains a list of valid response codes for responses that are okay to add to the cache.


### **EnforceTimeout**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag. If set to `true`, requests will enforce a configured timeout.

**Field: `value`**

**Type: `int`**

Value is the configured timeout in seconds.


### **ValidateRequest**

**Field: `enabled`**

**Type: `boolean`**

Enabled is a boolean flag, if set to `true`, it enables request validation.

**Field: `errorResponseCode`**

**Type: `int`**

ErrorResponseCode is the error code emitted when the request fails validation.
If unset or zero, the response will returned with http status 422 Unprocessable Entity.


### **MockResponse**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables the mock response middleware.

**Field: `code`**

**Type: `int`**

Code is the HTTP response code that will be returned.

**Field: `body`**

**Type: `string`**

Body is the HTTP response body that will be returned.

**Field: `headers`**

**Type: `string`**

Headers are the HTTP response headers that will be returned.

**Field: `fromOASExamples`**

**Type: [FromOASExamples](#fromoasexamples)**

FromOASExamples is the configuration to extract a mock response from OAS documentation.


### **FromOASExamples**

**Field: `enabled`**

**Type: `boolean`**

Enabled enables getting a mock response from OAS examples or schemas documented in OAS.

**Field: `code`**

**Type: `int`**

Code is the default HTTP response code that the gateway reads from the path responses documented in OAS.

**Field: `contentType`**

**Type: `string`**

ContentType is the default HTTP response body type that the gateway reads from the path responses documented in OAS.

**Field: `exampleName`**

**Type: `string`**

ExampleName is the default example name among multiple path response examples documented in OAS.


