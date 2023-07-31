
## TYK OAS API Definition Object

### **x-tyk-gateway**

**Field: `info` ([Info](#info))**
Info contains the main metadata about the API definition.

**Field: `upstream` ([Upstream](#upstream))**
Upstream contains the configurations related to the upstream.

**Field: `server` ([Server](#server))**
Server contains the configurations related to the server.

**Field: `middleware` ([Middleware](#middleware))**
Middleware contains the configurations related to the proxy middleware.


### **Info**

**Field: `id` (`string`)**
ID is the unique ID of the API.

Tyk classic API definition: `api_id`.

**Field: `dbId` (`object`)**
DBID is the unique database ID of the API.

Tyk classic API definition: `id`.

**Field: `orgId` (`string`)**
OrgID is the ID of the organisation which the API belongs to.

Tyk classic API definition: `org_id`.

**Field: `name` (`string`)**
Name is the name of the API.

Tyk classic API definition: `name`.

**Field: `expiration` (`string`)**
Expiration date.

**Field: `state` ([State](#state))**
State holds configuration about API definition states (active, internal).

**Field: `versioning` ([Versioning](#versioning))**
Versioning holds configuration for API versioning.


### **State**

**Field: `active` (`boolean`)**
Active enables the API.

Tyk classic API definition: `active`.

**Field: `internal` (`boolean`)**
Internal makes the API accessible only internally.

Tyk classic API definition: `internal`.


### **Versioning**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag, if set to `true` it will enable versioning of an API.

**Field: `name` (`string`)**
Name contains the name of the version as entered by the user ("v1" or similar).

**Field: `default` (`string`)**
Default contains the default version name if a request is issued without a version.

**Field: `location` (`string`)**
Location contains versioning location information. It can be one of the following:

- `header`,
- `url-param`,
- `url`.

**Field: `key` (`string`)**
Key contains the name of the key to check for versioning information.

**Field: `versions` (`[]`[VersionToID](#versiontoid))**
Versions contains a list of versions that map to individual API IDs.

**Field: `stripVersioningData` (`boolean`)**
StripVersioningData is a boolean flag, if set to `true`, the API responses will be stripped of versioning data.


### **VersionToID**

**Field: `name` (`string`)**
Name contains the user chosen version name, e.g. `v1` or similar.

**Field: `id` (`string`)**
ID is the API ID for the version set in Name.


### **Upstream**

**Field: `url` (`string`)**
URL defines the target URL that the request should be proxied to.

Tyk classic API definition: `proxy.target_url`.

**Field: `serviceDiscovery` ([ServiceDiscovery](#servicediscovery))**
ServiceDiscovery contains the configuration related to Service Discovery.

Tyk classic API definition: `proxy.service_discovery`.

**Field: `test` ([Test](#test))**
Test contains the configuration related to uptime tests.

**Field: `mutualTLS` ([MutualTLS](#mutualtls))**
MutualTLS contains the configuration related to upstream mutual TLS.

**Field: `certificatePinning` ([CertificatePinning](#certificatepinning))**
CertificatePinning contains the configuration related to certificate pinning.


### **ServiceDiscovery**

**Field: `enabled` (`boolean`)**
Enabled enables Service Discovery.

Tyk classic API definition: `service_discovery.use_discovery_service`.

**Field: `queryEndpoint` (`string`)**
QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.

Tyk classic API definition: `service_discovery.query_endpoint`.

**Field: `dataPath` (`string`)**
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

Tyk classic API definition: `service_discovery.data_path`.

**Field: `useNestedQuery` (`boolean`)**
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


Tyk classic API definition: `service_discovery.use_nested_query`.

**Field: `parentDataPath` (`string`)**
ParentDataPath is the namespace of the where to find the nested value, if `useNestedQuery` is `true`. In the above example, it would be `node.value`. You would change the `dataPath` setting to be `hostname`, since this is where the host name data resides in the JSON string. Tyk automatically assumes that `dataPath` in this case is in a string-encoded JSON object and will try to deserialize it.

Tyk classic API definition: `service_discovery.parent_data_path`.

**Field: `portDataPath` (`string`)**
PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath` as the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier such as `/widgets/`). In the above example, the `portDataPath` would be `port`.

Tyk classic API definition: `service_discovery.port_data_path`.

**Field: `useTargetList` (`boolean`)**
UseTargetList should be set to `true`, if you are using load balancing. Tyk will treat the data path as a list and inject it into the target list of your API definition.

Tyk classic API definition: `service_discovery.use_target_list`.

**Field: `cacheTimeout` (`int`)**
CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that failures are not recovered from quickly enough.
Deprecated: The field is deprecated, usage needs to be updated to configure caching.

Tyk classic API definition: `service_discovery.cache_timeout`.

**Field: `cache` ([ServiceDiscoveryCache](#servicediscoverycache))**
Cache holds cache related flags.

Tyk classic API definition:

- `service_discovery.cache_disabled`
- `service_discovery.cache_timeout`

**Field: `targetPath` (`string`)**
TargetPath is to set a target path to append to the discovered endpoint, since many SD services only provide host and port data. It is important to be able to target a specific resource on that host.
Setting this value will enable that.

Tyk classic API definition: `service_discovery.target_path`.

**Field: `endpointReturnsList` (`boolean`)**
EndpointReturnsList is set `true` when the response type is a list instead of an object.

Tyk classic API definition: `service_discovery.endpoint_returns_list`.


### **ServiceDiscoveryCache**

**Field: `enabled` (`boolean`)**
Enabled turns service discovery cache on or off.

Tyk classic API definition: `service_discovery.cache_disabled`.

**Field: `timeout` (`int`)**
Timeout is the TTL for a cached object in seconds.

Tyk classic API definition: `service_discovery.cache_timeout`.


### **Test**

**Field: `serviceDiscovery` ([ServiceDiscovery](#servicediscovery))**
ServiceDiscovery contains the configuration related to test Service Discovery.

Tyk classic API definition: `proxy.service_discovery`.


### **MutualTLS**

**Field: `enabled` (`boolean`)**
Enabled enables/disables upstream mutual TLS auth for the API.

Tyk classic API definition: `upstream_certificates_disabled`.

**Field: `domainToCertificateMapping` (`[]`[DomainToCertificate](#domaintocertificate))**
DomainToCertificates maintains the mapping of domain to certificate.

Tyk classic API definition: `upstream_certificates`.


### **DomainToCertificate**

**Field: `domain` (`string`)**
Domain contains the domain name.

**Field: `certificate` (`string`)**
Certificate contains the certificate mapped to the domain.


### **CertificatePinning**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag, if set to `true`, it enables certificate pinning for the API.

Tyk classic API definition: `certificate_pinning_disabled`.

**Field: `domainToPublicKeysMapping` (`[]`[PinnedPublicKey](#pinnedpublickey))**
DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.

Tyk classic API definition: `pinned_public_keys`.


### **PinnedPublicKey**

**Field: `domain` (`string`)**
Domain contains the domain name.

**Field: `publicKeys` (`[]string`)**
PublicKeys contains a list of the public keys pinned to the domain name.


### **Server**

**Field: `listenPath` ([ListenPath](#listenpath))**
ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on, that match this path will have the rules defined in the API definition applied.

**Field: `slug` (`string`)**
Slug is the Tyk Cloud equivalent of listen path.

Tyk classic API definition: `slug`.

**Field: `authentication` ([Authentication](#authentication))**
Authentication contains the configurations related to authentication to the API.

**Field: `clientCertificates` ([ClientCertificates](#clientcertificates))**
ClientCertificates contains the configurations related to static mTLS.

**Field: `gatewayTags` ([GatewayTags](#gatewaytags))**
GatewayTags contains segment tags to configure which GWs your APIs connect to.

**Field: `customDomain` ([Domain](#domain))**
CustomDomain is the domain to bind this API to.

Tyk classic API definition: `domain`.


### **ListenPath**

**Field: `value` (`string`)**
Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.

Tyk classic API definition: `proxy.listen_path`.

**Field: `strip` (`boolean`)**
Strip removes the inbound listen path in the outgoing request. e.g. `http://acme.com/httpbin/get` where `httpbin`is the listen path. The `httpbin` listen path which is used to identify the API loaded in Tyk is removed, and the outbound request would be `http://httpbin.org/get`.

Tyk classic API definition: `proxy.strip_listen_path`.


### **Authentication**

**Field: `enabled` (`boolean`)**
Enabled makes the API protected when one of the authentication modes is enabled.

Tyk classic API definition: `!use_keyless`.

**Field: `stripAuthorizationData` (`boolean`)**
StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not leaked to the upstream.

Tyk classic API definition: `strip_auth_data`.

**Field: `baseIdentityProvider` (`object`)**
BaseIdentityProvider enables multi authentication mechanism and provides the session object that determines rate limits, ACL rules and quotas.
It should be set to one of the following:

- `auth_token`
- `hmac_key`
- `basic_auth_user`
- `jwt_claim`
- `oidc_user`
- `oauth_key`
- `custom_auth`


Tyk classic API definition: `base_identity_provided_by`.

**Field: `hmac` ([HMAC](#hmac))**
HMAC contains the configurations related to HMAC authentication mode.

Tyk classic API definition: `auth_configs["hmac"]`.

**Field: `oidc` ([OIDC](#oidc))**
OIDC contains the configurations related to OIDC authentication mode.

Tyk classic API definition: `auth_configs["oidc"]`.

**Field: `custom` ([CustomPluginAuthentication](#custompluginauthentication))**
Custom contains the configurations related to Custom authentication mode.

Tyk classic API definition: `auth_configs["coprocess"]`.

**Field: `securitySchemes` (`map[string]any`)**
SecuritySchemes contains security schemes definitions.


### **HMAC**

**Field: `enabled` (`boolean`)**
Enabled enables the HMAC authentication mode.

Tyk classic API definition: `enable_signature_checking`.

**Field: `header` ([AuthSource](#authsource))**
Header contains configurations for the header value auth source, it is enabled by default.

Tyk classic API definition: `auth_configs[x].header`.

**Field: `cookie` ([AuthSource](#authsource))**
Cookie contains configurations for the cookie value auth source.

Tyk classic API definition: `auth_configs[x].cookie`.

**Field: `query` ([AuthSource](#authsource))**
Query contains configurations for the query parameters auth source.

Tyk classic API definition: `auth_configs[x].query`.

**Field: `allowedAlgorithms` (`[]string`)**
AllowedAlgorithms is the array of HMAC algorithms which are allowed. Tyk supports the following HMAC algorithms:

- `hmac-sha1`
- `hmac-sha256`
- `hmac-sha384`
- `hmac-sha512`

and reads the value from algorithm header.

Tyk classic API definition: `hmac_allowed_algorithms`.

**Field: `allowedClockSkew` (`double`)**
AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.
The default value is `0`, which deactivates clock skew checks.

Tyk classic API definition: `hmac_allowed_clock_skew`.


### **AuthSources**

**Field: `header` ([AuthSource](#authsource))**
Header contains configurations for the header value auth source, it is enabled by default.

Tyk classic API definition: `auth_configs[x].header`.

**Field: `cookie` ([AuthSource](#authsource))**
Cookie contains configurations for the cookie value auth source.

Tyk classic API definition: `auth_configs[x].cookie`.

**Field: `query` ([AuthSource](#authsource))**
Query contains configurations for the query parameters auth source.

Tyk classic API definition: `auth_configs[x].query`.


### **AuthSource**

**Field: `enabled` (`boolean`)**
Enabled enables the auth source.

Tyk classic API definition: `auth_configs[X].use_param/use_cookie`.

**Field: `name` (`string`)**
Name is the name of the auth source.

Tyk classic API definition: `auth_configs[X].param_name/cookie_name`.


### **OIDC**

**Field: `enabled` (`boolean`)**
Enabled enables the OIDC authentication mode.

Tyk classic API definition: `use_openid`.

**Field: `header` ([AuthSource](#authsource))**
Header contains configurations for the header value auth source, it is enabled by default.

Tyk classic API definition: `auth_configs[x].header`.

**Field: `cookie` ([AuthSource](#authsource))**
Cookie contains configurations for the cookie value auth source.

Tyk classic API definition: `auth_configs[x].cookie`.

**Field: `query` ([AuthSource](#authsource))**
Query contains configurations for the query parameters auth source.

Tyk classic API definition: `auth_configs[x].query`.

**Field: `segregateByClientId` (`boolean`)**
SegregateByClientId is a boolean flag. If set to `true, the policies will be applied to a combination of Client ID and User ID.

Tyk classic API definition: `openid_options.segregate_by_client`.

**Field: `providers` (`[]`[Provider](#provider))**
Providers contains a list of authorised providers and their Client IDs, and matched policies.

Tyk classic API definition: `openid_options.providers`.

**Field: `scopes` ([Scopes](#scopes))**
Scopes contains the defined scope claims.


### **Provider**

**Field: `issuer` (`string`)**
Issuer contains a validation value for the issuer claim, usually a domain name e.g. `accounts.google.com` or similar.

**Field: `clientToPolicyMapping` (`[]`[ClientToPolicy](#clienttopolicy))**
ClientToPolicyMapping contains mappings of Client IDs to Policy IDs.


### **ClientToPolicy**

**Field: `clientId` (`string`)**
ClientID contains a Client ID.

**Field: `policyId` (`string`)**
PolicyID contains a Policy ID.


### **Scopes**

**Field: `claimName` (`string`)**
ClaimName contains the claim name.

**Field: `scopeToPolicyMapping` (`[]`[ScopeToPolicy](#scopetopolicy))**
ScopeToPolicyMapping contains the mappings of scopes to policy IDs.


### **ScopeToPolicy**

**Field: `scope` (`string`)**
Scope contains the scope name.

**Field: `policyId` (`string`)**
PolicyID contains the Policy ID.


### **CustomPluginAuthentication**

**Field: `enabled` (`boolean`)**
Enabled enables the CustomPluginAuthentication authentication mode.

Tyk classic API definition: `enable_coprocess_auth`/`use_go_plugin_auth`.

**Field: `config` ([AuthenticationPlugin](#authenticationplugin))**
Config contains configuration related to custom authentication plugin.

Tyk classic API definition: `custom_middleware.auth_check`.

**Field: `header` ([AuthSource](#authsource))**
Header contains configurations for the header value auth source, it is enabled by default.

Tyk classic API definition: `auth_configs[x].header`.

**Field: `cookie` ([AuthSource](#authsource))**
Cookie contains configurations for the cookie value auth source.

Tyk classic API definition: `auth_configs[x].cookie`.

**Field: `query` ([AuthSource](#authsource))**
Query contains configurations for the query parameters auth source.

Tyk classic API definition: `auth_configs[x].query`.


### **AuthenticationPlugin**

**Field: `enabled` (`boolean`)**
Enabled enables custom authentication plugin.

**Field: `functionName` (`string`)**
FunctionName is the name of authentication method.

**Field: `path` (`string`)**
Path is the path to shared object file in case of gopluign mode or path to js code in case of otto auth plugin.

**Field: `rawBodyOnly` (`boolean`)**
RawBodyOnly if set to true, do not fill body in request or response object.

**Field: `idExtractor` ([IDExtractor](#idextractor))**
IDExtractor configures ID extractor with coprocess custom authentication.


### **IDExtractor**

**Field: `enabled` (`boolean`)**
Enabled enables ID extractor with coprocess authentication.

**Field: `source` (`object`)**
Source is the source from which ID to be extracted from.

**Field: `with` (`object`)**
With is the type of ID extractor to be used.

**Field: `config` ([IDExtractorConfig](#idextractorconfig))**
Config holds the configuration specific to ID extractor type mentioned via With.


### **IDExtractorConfig**

**Field: `headerName` (`string`)**
HeaderName is the header name to extract ID from.

**Field: `formParamName` (`string`)**
FormParamName is the form parameter name to extract ID from.

**Field: `regexp` (`string`)**
Regexp is the regular expression to match ID.

**Field: `regexpMatchIndex` (`int`)**
RegexpMatchIndex is the index from which ID to be extracted after a match.
Default value is 0, ie if regexpMatchIndex is not provided ID is matched from index 0.

**Field: `xPathExp` (`string`)**
XPathExp is the xpath expression to match ID.


### **ClientCertificates**

**Field: `enabled` (`boolean`)**
Enabled enables static mTLS for the API.

**Field: `allowlist` (`[]string`)**
Allowlist is the list of client certificates which are allowed.


### **GatewayTags**

**Field: `enabled` (`boolean`)**
Enabled enables use of segment tags.

**Field: `tags` (`[]string`)**
Tags is a list of segment tags


### **Domain**

**Field: `enabled` (`boolean`)**
Enabled allow/disallow the usage of the domain.

**Field: `name` (`string`)**
Name is the name of the domain.


### **Middleware**

**Field: `global` ([Global](#global))**
Global contains the configurations related to the global middleware.

**Field: `operations` (`map[string]`[Operation](#operation))**
Operations configuration.


### **Global**

**Field: `pluginConfig` ([PluginConfig](#pluginconfig))**
PluginConfig contains the configuration related custom plugin bundles/driver.

**Field: `cors` ([CORS](#cors))**
CORS contains the configuration related to cross origin resource sharing.

Tyk classic API definition: `CORS`.

**Field: `prePlugin` ([PrePlugin](#preplugin))**
PrePlugin contains configuration related to custom pre-authentication plugin.

Tyk classic API definition: `custom_middleware.pre`.

**Field: `postAuthenticationPlugin` ([PostAuthenticationPlugin](#postauthenticationplugin))**
PostAuthenticationPlugin contains configuration related to custom post authentication plugin.

Tyk classic API definition: `custom_middleware.post_key_auth`.

**Field: `postPlugin` ([PostPlugin](#postplugin))**
PostPlugin contains configuration related to custom post plugin.

Tyk classic API definition: `custom_middleware.post`.

**Field: `responsePlugin` ([ResponsePlugin](#responseplugin))**
ResponsePlugin contains configuration related to custom post plugin.

Tyk classic API definition: `custom_middleware.response`.

**Field: `cache` ([Cache](#cache))**
Cache contains the configurations related to caching.

Tyk classic API definition: `cache_options`.


### **PluginConfig**

**Field: `driver` (`object`)**
Driver configures which custom plugin to be used.
It's value should be set to one of the following:

- `otto`,
- `python`,
- `lua`,
- `grpc`,
- `goplugin`.


Tyk classic API definition: `custom_middleware.driver`.

**Field: `bundle` ([PluginBundle](#pluginbundle))**
Bundle configures custom plugin bundles.

**Field: `data` ([PluginConfigData](#pluginconfigdata))**
Data configures custom plugin data.


### **PluginBundle**

**Field: `enabled` (`boolean`)**
Enabled enables the custom plugin bundles.

Tyk classic API definition: `custom_middleware_bundle_disabled`.

**Field: `path` (`string`)**
Path is the path suffix to construct the URL to fetch plugin bundle from.
Path will be suffixed to `bundle_base_url` in gateway config.


### **PluginConfigData**

**Field: `enabled` (`boolean`)**
Enabled enables custom plugin config data.

**Field: `value` (`any`)**
Value is the value of custom plugin config data.


### **CORS**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag, if set to `true`, this option enables CORS processing.

Tyk classic API definition: `CORS.enable`.

**Field: `maxAge` (`int`)**
MaxAge indicates how long (in seconds) the results of a preflight request can be cached. The default is 0 which stands for no max age.

Tyk classic API definition: `CORS.max_age`.

**Field: `allowCredentials` (`boolean`)**
AllowCredentials indicates whether the request can include user credentials like cookies, HTTP authentication or client side SSL certificates.

Tyk classic API definition: `CORS.allow_credentials`.

**Field: `exposedHeaders` (`[]string`)**
ExposedHeaders indicates which headers are safe to expose to the API of a CORS API specification.

Tyk classic API definition: `CORS.exposed_headers`.

**Field: `allowedHeaders` (`[]string`)**
AllowedHeaders holds a list of non simple headers the client is allowed to use with cross-domain requests.

Tyk classic API definition: `CORS.allowed_headers`.

**Field: `optionsPassthrough` (`boolean`)**
OptionsPassthrough is a boolean flag. If set to `true`, it will proxy the CORS OPTIONS pre-flight request directly to upstream, without authentication and any CORS checks. This means that pre-flight requests generated by web-clients such as SwaggerUI or the Tyk Portal documentation system will be able to test the API using trial keys.
If your service handles CORS natively, then enable this option.

Tyk classic API definition: `CORS.options_passthrough`.

**Field: `debug` (`boolean`)**
Debug is a boolean flag, If set to `true`, this option produces log files for the CORS middleware.

Tyk classic API definition: `CORS.debug`.

**Field: `allowedOrigins` (`[]string`)**
AllowedOrigins holds a list of origin domains to allow access from. Wildcards are also supported, e.g. `http://*.foo.com`.

Tyk classic API definition: `CORS.allowed_origins`.

**Field: `allowedMethods` (`[]string`)**
AllowedMethods holds a list of methods to allow access via.

Tyk classic API definition: `CORS.allowed_methods`.


### **PrePlugin**

**Field: `plugins` (`[]`[CustomPlugin](#customplugin))**
Plugins configures custom plugins to be run on pre authentication stage.
The plugins would be executed in the order of configuration in the list.


### **CustomPlugin**

**Field: `enabled` (`boolean`)**
Enabled enables the custom pre plugin.

**Field: `functionName` (`string`)**
FunctionName is the name of authentication method.

**Field: `path` (`string`)**
Path is the path to shared object file in case of gopluign mode or path to js code in case of otto auth plugin.

**Field: `rawBodyOnly` (`boolean`)**
RawBodyOnly if set to true, do not fill body in request or response object.

**Field: `requireSession` (`boolean`)**
RequireSession if set to true passes down the session information for plugins after authentication.
RequireSession is used only with JSVM custom middleware.


### **PostAuthenticationPlugin**

**Field: `plugins` (`[]`[CustomPlugin](#customplugin))**
Plugins configures custom plugins to be run on pre authentication stage.
The plugins would be executed in the order of configuration in the list.


### **PostPlugin**

**Field: `plugins` (`[]`[CustomPlugin](#customplugin))**
Plugins configures custom plugins to be run on post stage.
The plugins would be executed in the order of configuration in the list.


### **ResponsePlugin**

**Field: `plugins` (`[]`[CustomPlugin](#customplugin))**
Plugins configures custom plugins to be run on post stage.
The plugins would be executed in the order of configuration in the list.


### **Cache**

**Field: `enabled` (`boolean`)**
Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis by explicitly setting the endpoint cache middleware.

Tyk classic API definition: `cache_options.enable_cache`.

**Field: `timeout` (`int`)**
Timeout is the TTL for a cached object in seconds.

Tyk classic API definition: `cache_options.cache_timeout`.

**Field: `cacheAllSafeRequests` (`boolean`)**
CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions, applies across versions.

Tyk classic API definition: `cache_options.cache_all_safe_requests`.

**Field: `cacheResponseCodes` (`[]int`)**
CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.

Tyk classic API definition: `cache_options.cache_response_codes`.

**Field: `cacheByHeaders` (`[]string`)**
CacheByHeaders allows header values to be used as part of the cache key.

Tyk classic API definition: `cache_options.cache_by_headers`.

**Field: `enableUpstreamCacheControl` (`boolean`)**
EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.

Tyk classic API definition: `cache_options.enable_upstream_cache_control`.

**Field: `controlTTLHeaderName` (`string`)**
ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.

Tyk classic API definition: `cache_options.cache_control_ttl_header`.


### **Operation**

**Field: `allow` ([Allowance](#allowance))**
Allow request by allowance.

**Field: `block` ([Allowance](#allowance))**
Block request by allowance.

**Field: `ignoreAuthentication` ([Allowance](#allowance))**
IgnoreAuthentication ignores authentication on request by allowance.

**Field: `transformRequestMethod` ([TransformRequestMethod](#transformrequestmethod))**
TransformRequestMethod allows you to transform the method of a request.

**Field: `transformRequestBody` ([TransformBody](#transformbody))**
TransformRequestBody allows you to transform request body.
When both `path` and `body` are provided, body would take precedence.

**Field: `transformResponseBody` ([TransformBody](#transformbody))**
TransformResponseBody allows you to transform response body.
When both `path` and `body` are provided, body would take precedence.

**Field: `cache` ([CachePlugin](#cacheplugin))**
Cache contains the caching plugin configuration.

**Field: `enforceTimeout` ([EnforceTimeout](#enforcetimeout))**
EnforceTimeout contains the request timeout configuration.

**Field: `validateRequest` ([ValidateRequest](#validaterequest))**
ValidateRequest contains the request validation configuration.

**Field: `mockResponse` ([MockResponse](#mockresponse))**
MockResponse contains the mock response configuration.

**Field: `virtualEndpoint` ([VirtualEndpoint](#virtualendpoint))**
VirtualEndpoint contains virtual endpoint configuration.

**Field: `postPlugins` (`[]`[EndpointPostPlugin](#endpointpostplugin))**
PostPlugins contains endpoint level post plugins configuration.


### **Allowance**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag, if set to `true`, then individual allowances (allow, block, ignore) will be enforced.

**Field: `ignoreCase` (`boolean`)**
IgnoreCase is a boolean flag, If set to `true`, checks for requests allowance will be case insensitive.


### **TransformRequestMethod**

**Field: `enabled` (`boolean`)**
Enabled enables Method Transform for the given path and method.

**Field: `toMethod` (`string`)**
ToMethod is the http method value to which the method of an incoming request will be transformed.


### **TransformBody**

**Field: `enabled` (`boolean`)**
Enabled enables transform request/request body middleware.

**Field: `format` (`object`)**
Format of the request/response body, xml or json.

**Field: `path` (`string`)**
Path file path for the template.

**Field: `body` (`string`)**
Body base64 encoded representation of the template.


### **CachePlugin**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag. If set to `true`, the advanced caching plugin will be enabled.

**Field: `cacheByRegex` (`string`)**
CacheByRegex defines a regular expression used against the request body to produce a cache key.
Example value: `\"id\":[^,]*` (quoted json value).

**Field: `cacheResponseCodes` (`[]int`)**
CacheResponseCodes contains a list of valid response codes for responses that are okay to add to the cache.

**Field: `timeout` (`int`)**
Timeout is the TTL for the endpoint level caching in seconds. 0 means no caching.


### **EnforceTimeout**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag. If set to `true`, requests will enforce a configured timeout.

**Field: `value` (`int`)**
Value is the configured timeout in seconds.


### **ValidateRequest**

**Field: `enabled` (`boolean`)**
Enabled is a boolean flag, if set to `true`, it enables request validation.

**Field: `errorResponseCode` (`int`)**
ErrorResponseCode is the error code emitted when the request fails validation.
If unset or zero, the response will returned with http status 422 Unprocessable Entity.


### **MockResponse**

**Field: `enabled` (`boolean`)**
Enabled enables the mock response middleware.

**Field: `code` (`int`)**
Code is the HTTP response code that will be returned.

**Field: `body` (`string`)**
Body is the HTTP response body that will be returned.

**Field: `headers` (`[]`[Header](#header))**
Headers are the HTTP response headers that will be returned.

**Field: `fromOASExamples` ([FromOASExamples](#fromoasexamples))**
FromOASExamples is the configuration to extract a mock response from OAS documentation.


### **Header**

**Field: `name` (`string`)**
Name is the name of the header.

**Field: `value` (`string`)**
Value is the value of the header.


### **FromOASExamples**

**Field: `enabled` (`boolean`)**
Enabled enables getting a mock response from OAS examples or schemas documented in OAS.

**Field: `code` (`int`)**
Code is the default HTTP response code that the gateway reads from the path responses documented in OAS.

**Field: `contentType` (`string`)**
ContentType is the default HTTP response body type that the gateway reads from the path responses documented in OAS.

**Field: `exampleName` (`string`)**
ExampleName is the default example name among multiple path response examples documented in OAS.


### **VirtualEndpoint**

**Field: `enabled` (`boolean`)**
Enabled enables virtual endpoint.

**Field: `name` (`string`)**
Name is the name of js function.

**Field: `path` (`string`)**
Path is the path to js file.

**Field: `body` (`string`)**
Body is the js function to execute encoded in base64 format.

**Field: `proxyOnError` (`boolean`)**
ProxyOnError proxies if virtual endpoint errors out.

**Field: `requireSession` (`boolean`)**
RequireSession if enabled passes session to virtual endpoint.


### **EndpointPostPlugin**

**Field: `enabled` (`boolean`)**
Enabled enables post plugin.

**Field: `name` (`string`)**
Name is the name of plugin function to be executed.

**Field: `path` (`string`)**
Path is the path to plugin.


