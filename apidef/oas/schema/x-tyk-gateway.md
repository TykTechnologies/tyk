
## Documentation of X-Tyk-Gateway Object

### **x-tyk-gateway**

- `info`

  **Type: [Info](#info)**

  Info contains the main metadata about the API definition.

- `upstream`

  **Type: [Upstream](#upstream)**

  Upstream contains the configurations related to the upstream.

- `server`

  **Type: [Server](#server)**

  Server contains the configurations related to the server.

- `middleware`

  **Type: [Middleware](#middleware)**

  Middleware contains the configurations related to the proxy middleware.


### **Info**

- `id`

  **Type: `string`**

  ID is the unique ID of the API.

  Old API Definition: `api_id`

- `dbId`

  **Type: `object`**

  DBID is the unique database ID of the API.

  Old API Definition: `id`

- `orgId`

  **Type: `string`**

  OrgID is the ID of the organisation which the API belongs to.

  Old API Definition: `org_id`

- `name`

  **Type: `string`**

  Name is the name of the API.

  Old API Definition: `name`

- `expiration`

  **Type: `string`**

- `state`

  **Type: [State](#state)**

- `versioning`

  **Type: [Versioning](#versioning)**


### **State**

- `active`

  **Type: `boolean`**

  Active enables the API.

  Old API Definition: `active`

- `internal`

  **Type: `boolean`**

  Internal makes the API accessible only internally.

  Old API Definition: `internal`


### **Versioning**

- `enabled`

  **Type: `boolean`**

- `name`

  **Type: `string`**

- `default`

  **Type: `string`**

- `location`

  **Type: `string`**

- `key`

  **Type: `string`**

- `versions`

  **Type: [[]VersionToID](#versiontoid)**

- `stripVersioningData`

  **Type: `boolean`**


### **VersionToID**

- `name`

  **Type: `string`**

- `id`

  **Type: `string`**


### **Upstream**

- `url`

  **Type: `string`**

  URL defines the target URL that the request should be proxied to.

  Old API Definition: `proxy.target_url`

- `serviceDiscovery`

  **Type: [ServiceDiscovery](#servicediscovery)**

  ServiceDiscovery contains the configuration related to Service Discovery.

  Old API Definition: `proxy.service_discovery`

- `test`

  **Type: [Test](#test)**

  Test contains the configuration related to uptime tests.

- `mutualTLS`

  **Type: [MutualTLS](#mutualtls)**

  MutualTLS contains the configuration related to upstream mutual TLS.

- `certificatePinning`

  **Type: [CertificatePinning](#certificatepinning)**

  CertificatePinning contains the configuration related to certificate pinning.


### **ServiceDiscovery**

- `enabled`

  **Type: `boolean`**

  Enabled enables Service Discovery.

  Old API Definition: `service_discovery.use_discovery_service`

- `queryEndpoint`

  **Type: `string`**

  QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.

  Old API Definition: `service_discovery.query_endpoint`

- `dataPath`

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

  Old API Definition: `service_discovery.data_path`

- `useNestedQuery`

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

  Old API Definition: `service_discovery.use_nested_query`

- `parentDataPath`

  **Type: `string`**

  ParentDataPath is the namespace of the where to find the nested value, if `useNestedQuery` is `true`.

  In the above example, it would be `node.value`. You would then change the `dataPath` setting to be `hostname`,

  since this is where the host name data resides in the JSON string.

  Tyk automatically assumes that `dataPath` in this case is in a string-encoded JSON object and will try to deserialize it.

  Old API Definition: `service_discovery.parent_data_path`

- `portDataPath`

  **Type: `string`**

  PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value

  for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath`

  as the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier

  such as `/widgets/`). In the above example, the `portDataPath` would be `port`.

  Old API Definition: `service_discovery.port_data_path`

- `useTargetList`

  **Type: `boolean`**

  UseTargetList should be set to `true`, if you are using load balancing. Tyk will treat the data path as a list and

  inject it into the target list of your API Definition.

  Old API Definition: `service_discovery.use_target_list`

- `cacheTimeout`

  **Type: `int`**

  CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.

  Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that

  failures are not recovered from quickly enough.

  Old API Definition: `service_discovery.cache_timeout`

- `targetPath`

  **Type: `string`**

  TargetPath is to set a target path to append to the discovered endpoint, since many SD services

  only provide host and port data. It is important to be able to target a specific resource on that host.

  Setting this value will enable that.

  Old API Definition: `service_discovery.target_path`

- `endpointReturnsList`

  **Type: `boolean`**

  EndpointReturnsList is set `true` when the response type is a list instead of an object.

  Old API Definition: `service_discovery.endpoint_returns_list`


### **Test**

- `serviceDiscovery`

  **Type: [ServiceDiscovery](#servicediscovery)**

  ServiceDiscovery contains the configuration related to test Service Discovery.

  Old API Definition: `proxy.service_discovery`


### **MutualTLS**

- `enabled`

  **Type: `boolean`**

  Enabled enables/disables upstream mutual TLS auth for the API.

  Old API Definition: `upstream_certificates_disabled`

- `domainToCertificateMapping`

  **Type: [[]DomainToCertificate](#domaintocertificate)**

  DomainToCertificate maintains the mapping of domain to certificate.

  Old API Definition: `upstream_certificates`


### **DomainToCertificate**

- `domain`

  **Type: `string`**

- `certificate`

  **Type: `string`**


### **CertificatePinning**

- `enabled`

  **Type: `boolean`**

  Enabled enables/disables certificate pinning for the API.

  Old API Definition: `certificate_pinning_disabled`

- `domainToPublicKeysMapping`

  **Type: [[]PinnedPublicKey](#pinnedpublickey)**

  DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.

  Old API Definition: `pinned_public_keys`


### **PinnedPublicKey**

- `domain`

  **Type: `string`**

- `publicKeys`

  **Type: `[]string`**


### **Server**

- `listenPath`

  **Type: [ListenPath](#listenpath)**

  ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on,

  that match this path will have the rules defined in the API Definition applied.

- `slug`

  **Type: `string`**

  Slug is the Tyk Cloud equivalent of listen path.

  Old API Definition: `slug`

- `authentication`

  **Type: [Authentication](#authentication)**

  Authentication contains the configurations related to authentication to the API.

- `clientCertificates`

  **Type: [ClientCertificates](#clientcertificates)**

  ClientCertificates contains the configurations related to static mTLS.

- `gatewayTags`

  **Type: [GatewayTags](#gatewaytags)**

  GatewayTags contains segment tags to configure which GWs your APIs connect to

- `customDomain`

  **Type: [Domain](#domain)**

  CustomDomain is the domain to bind this API to.

  Old API Definition: `domain`


### **ListenPath**

- `value`

  **Type: `string`**

  Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.

  Old API Definition: `proxy.listen_path`

- `strip`

  **Type: `boolean`**

  Strip removes the inbound listen path in the outgoing request. e.g. `http://acme.com/httpbin/get` where `httpbin`

  is the listen path. The `httpbin` listen path which is used to identify the API loaded in Tyk is removed,

  and the outbound request would be `http://httpbin.org/get`.

  Old API Definition: `proxy.strip_listen_path`


### **Authentication**

- `enabled`

  **Type: `boolean`**

  Enabled makes the API protected when one of the authentication modes is enabled.

  Old API Definition: `!use_keyless`

- `stripAuthorizationData`

  **Type: `boolean`**

  StripAuthorizationData ensures that any security tokens used for accessing APIs are stripped and not leaked to the upstream.

  Old API Definition: `strip_auth_data`

- `baseIdentityProvider`

  **Type: `object`**

  BaseIdentityProvider enables multi authentication mechanism and provides the session object that determines rate limits, ACL rules and quotas.

  It should be set to one of the following:

  - `auth_token`

  - `hmac_key`

  - `basic_auth_user`

  - `jwt_claim`

  - `oidc_user`

  - `oauth_key`

  Old API Definition: `base_identity_provided_by`

- `hmac`

  **Type: [HMAC](#hmac)**

  HMAC contains the configurations related to HMAC authentication mode.

  Old API Definition: `auth_configs["hmac"]`

- `oidc`

  **Type: [OIDC](#oidc)**

  OIDC contains the configurations related to OIDC authentication mode.

  Old API Definition: `auth_configs["oidc"]`

- `goPlugin`

  **Type: [GoPlugin](#goplugin)**

  GoPlugin contains the configurations related to GoPlugin authentication mode.

- `customPlugin`

  **Type: [CustomPlugin](#customplugin)**

  CustomPlugin contains the configurations related to CustomPlugin authentication mode.

  Old API Definition: `auth_configs["coprocess"]`

- `securitySchemes`

  **Type: `map[string]any`**


### **HMAC**

- `enabled`

  **Type: `boolean`**

  Enabled enables the HMAC authentication mode.

  Old API Definition: `enable_signature_checking`

- `header`

  **Type: [AuthSource](#authsource)**

  Header contains configurations of the header auth source, it is enabled by default.

  Old API Definition:

- `cookie`

  **Type: [AuthSource](#authsource)**

  Cookie contains configurations of the cookie auth source.

  Old API Definition: `api_id`

- `query`

  **Type: [AuthSource](#authsource)**

  Param contains configurations of the param auth source.

  Old API Definition: `api_id`

- `allowedAlgorithms`

  **Type: `[]string`**

  AllowedAlgorithms is the array of HMAC algorithms which are allowed. Tyk supports the following HMAC algorithms:

  - `hmac-sha1`

  - `hmac-sha256`

  - `hmac-sha384`

  - `hmac-sha512`

  and reads the value from algorithm header.

  Old API Definition: `hmac_allowed_algorithms`

- `allowedClockSkew`

  **Type: `double`**

  AllowedClockSkew is the amount of milliseconds that will be tolerated for clock skew. It is used against replay attacks.

  The default value is `0`, which deactivates clock skew checks.

  Old API Definition: `hmac_allowed_clock_skew`


### **AuthSources**

- `header`

  **Type: [AuthSource](#authsource)**

  Header contains configurations of the header auth source, it is enabled by default.

  Old API Definition:

- `cookie`

  **Type: [AuthSource](#authsource)**

  Cookie contains configurations of the cookie auth source.

  Old API Definition: `api_id`

- `query`

  **Type: [AuthSource](#authsource)**

  Param contains configurations of the param auth source.

  Old API Definition: `api_id`


### **AuthSource**

- `enabled`

  **Type: `boolean`**

  Enabled enables the auth source.

  Old API Definition: `auth_configs[X].use_param/use_cookie`

- `name`

  **Type: `string`**

  Name is the name of the auth source.

  Old API Definition: `auth_configs[X].param_name/cookie_name`


### **OIDC**

- `enabled`

  **Type: `boolean`**

  Enabled enables the OIDC authentication mode.

  Old API Definition: `use_openid`

- `header`

  **Type: [AuthSource](#authsource)**

  Header contains configurations of the header auth source, it is enabled by default.

  Old API Definition:

- `cookie`

  **Type: [AuthSource](#authsource)**

  Cookie contains configurations of the cookie auth source.

  Old API Definition: `api_id`

- `query`

  **Type: [AuthSource](#authsource)**

  Param contains configurations of the param auth source.

  Old API Definition: `api_id`

- `segregateByClientId`

  **Type: `boolean`**

- `providers`

  **Type: [[]Provider](#provider)**

- `scopes`

  **Type: [Scopes](#scopes)**


### **Provider**

- `issuer`

  **Type: `string`**

- `clientToPolicyMapping`

  **Type: [[]ClientToPolicy](#clienttopolicy)**


### **ClientToPolicy**

- `clientId`

  **Type: `string`**

- `policyId`

  **Type: `string`**


### **Scopes**

- `claimName`

  **Type: `string`**

- `scopeToPolicyMapping`

  **Type: [[]ScopeToPolicy](#scopetopolicy)**


### **ScopeToPolicy**

- `scope`

  **Type: `string`**

- `policyId`

  **Type: `string`**


### **GoPlugin**

- `enabled`

  **Type: `boolean`**

  Enabled enables the GoPlugin authentication mode.

  Old API Definition: `use_go_plugin_auth`


### **CustomPlugin**

- `enabled`

  **Type: `boolean`**

  Enabled enables the CustomPlugin authentication mode.

  Old API Definition: `enable_coprocess_auth`

- `header`

  **Type: [AuthSource](#authsource)**

  Header contains configurations of the header auth source, it is enabled by default.

  Old API Definition:

- `cookie`

  **Type: [AuthSource](#authsource)**

  Cookie contains configurations of the cookie auth source.

  Old API Definition: `api_id`

- `query`

  **Type: [AuthSource](#authsource)**

  Param contains configurations of the param auth source.

  Old API Definition: `api_id`


### **ClientCertificates**

- `enabled`

  **Type: `boolean`**

  Enabled enables static mTLS for the API.

- `allowlist`

  **Type: `[]string`**

  AllowList is the list of client certificates which are allowed.


### **GatewayTags**

- `enabled`

  **Type: `boolean`**

  Enabled enables use of segment tags.

- `tags`

  **Type: `[]string`**

  Tags is a list of segment tags


### **Domain**

- `enabled`

  **Type: `boolean`**

  Enabled allow/disallow the usage of the domain.

- `name`

  **Type: `string`**

  Name is the name of the domain.


### **Middleware**

- `global`

  **Type: [Global](#global)**

  Global contains the configurations related to the global middleware.

- `operations`

  **Type: [map[string]Operation](#operation)**


### **Global**

- `cors`

  **Type: [CORS](#cors)**

- `cache`

  **Type: [Cache](#cache)**

  Cache contains the configurations related to caching.

  Old API Definition: `cache_options`


### **CORS**

- `enabled`

  **Type: `boolean`**

- `maxAge`

  **Type: `int`**

- `allowCredentials`

  **Type: `boolean`**

- `exposedHeaders`

  **Type: `[]string`**

- `allowedHeaders`

  **Type: `[]string`**

- `optionsPassthrough`

  **Type: `boolean`**

- `debug`

  **Type: `boolean`**

- `allowedOrigins`

  **Type: `[]string`**

- `allowedMethods`

  **Type: `[]string`**


### **Cache**

- `enabled`

  **Type: `boolean`**

  Enabled turns global cache middleware on or off. It is still possible to enable caching on a per-path basis

  by explicitly setting the endpoint cache middleware.

  Old API Definition: `cache_options.enable_cache`

- `timeout`

  **Type: `int`**

  Timeout is the TTL for a cached object in seconds.

  Old API Definition: `cache_options.cache_timeout`

- `cacheAllSafeRequests`

  **Type: `boolean`**

  CacheAllSafeRequests caches responses to (`GET`, `HEAD`, `OPTIONS`) requests overrides per-path cache settings in versions,

  applies across versions.

  Old API Definition: `cache_options.cache_all_safe_requests`

- `cacheResponseCodes`

  **Type: `[]int`**

  CacheResponseCodes is an array of response codes which are safe to cache e.g. `404`.

  Old API Definition: `cache_options.cache_response_codes`

- `cacheByHeaders`

  **Type: `[]string`**

  CacheByHeaders allows header values to be used as part of the cache key.

  Old API Definition: `cache_options.cache_by_headers`

- `enableUpstreamCacheControl`

  **Type: `boolean`**

  EnableUpstreamCacheControl instructs Tyk Cache to respect upstream cache control headers.

  Old API Definition: `cache_options.enable_upstream_cache_control`

- `controlTTLHeaderName`

  **Type: `string`**

  ControlTTLHeaderName is the response header which tells Tyk how long it is safe to cache the response for.

  Old API Definition: `cache_options.cache_control_ttl_header`


### **Operation**

- `allow`

  **Type: [Allowance](#allowance)**

- `block`

  **Type: [Allowance](#allowance)**

- `ignoreAuthentication`

  **Type: [Allowance](#allowance)**

- `transformRequestMethod`

  **Type: [TransformRequestMethod](#transformrequestmethod)**

  TransformRequestMethod allows you to transform the method of a request.

- `cache`

  **Type: [CachePlugin](#cacheplugin)**

- `enforceTimeout`

  **Type: [EnforceTimeout](#enforcetimeout)**

- `validateRequest`

  **Type: [ValidateRequest](#validaterequest)**


### **Allowance**

- `enabled`

  **Type: `boolean`**

- `ignoreCase`

  **Type: `boolean`**


### **TransformRequestMethod**

- `enabled`

  **Type: `boolean`**

  Enabled enables Method Transform for the given path and method.

- `toMethod`

  **Type: `string`**

  ToMethod is the http method value to which the method of an incoming request will be transformed.


### **CachePlugin**

- `enabled`

  **Type: `boolean`**

- `cacheByRegex`

  **Type: `string`**

- `cacheResponseCodes`

  **Type: `[]int`**


### **EnforceTimeout**

- `enabled`

  **Type: `boolean`**

- `value`

  **Type: `int`**


### **ValidateRequest**

- `enabled`

  **Type: `boolean`**

- `errorResponseCode`

  **Type: `int`**


