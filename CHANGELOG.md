# Develop

- It is now possible to separate out the cache data store from the main redis store
- Context Data now includes JWT Claims, claims are added as individual keys as $tyk_context.jwt_claims_CLAIMNAME.
- Meta data is now available to the URL Rewriter (for e.g. to inject a custom querystring for key holders.)
- Added API to invalidate a cache for an API: `DELETE /tyk/cache/{api-id}`
- It is now possible to rewrite a URL with a new host and have the host act as an override to any target settings that are in the API Definition
- Added more remote logger support: Graylog, Syslog and Logstash
- Added a global setting for middleware bundles, to set the global base URL for middleware bundles use `"bundle_base_url":"http://mybundles.com/"` in tyk.conf.
- The error handler now supports custom error templates. XML templates are supported as well. It's possible to have templates for specific HTTP errors, like "error_500.json".

### Graylog:

    "use_graylog": true,
    "graylog_network_addr": "<graylog_ip>:<graylog_port>"

### Syslog

If the transport or address are empty, syslog will log to file

    "use_syslog": true,
    "syslog_transport": "udp" | "",
    "syslog_network_addr:  "172.17.0.2:9999" | "",

### Logstash

    "use_logstash": "true"
    "logstash_transport": "tcp",
    "logstash_network_addr": "172.17.0.2:9999"

- Added support for multiple auth methods to be chained, e.g. Basic Auth and Standard auth tokens. This can be tricky because you must also specify which auth mechanism will provide the baseline identity that Tyk will use for applying rate limits / quotas, to set this, set the field: `base_identity_provided_by` to one of the enums below:

    AuthToken     AuthTypeEnum = "auth_token"
    HMACKey       AuthTypeEnum = "hmac_key"
    BasicAuthUser AuthTypeEnum = "basic_auth_user"
    JWTClaim      AuthTypeEnum = "jwt_claim"
    OIDCUser      AuthTypeEnum = "oidc_user"
    OAuthKey      AuthTypeEnum = "oauth_key"
    UnsetAuth     AuthTypeEnum = ""

- (multi-auth continued) Tyk will chain the auth mechanisms as they appear in the code and will default to auth token if none are specified. You can explicitly set auth token by setting `use_standard_auth` to true.
- It's now possible to write custom middleware in Python (see [Coprocess](https://github.com/TykTechnologies/tyk/tree/experiment/coprocess/coprocess)).
- Tyk gateway can now be hot-restarted with a new configuration / binary using the -SUGUSR2 signal
- Tyk gateway (with dashboard) no longer needs the dashboard URL configured as it will auto-discover this so long as it is set in the dashboard configuration file
- Tyk Gateway now uses "lazy loading" of middleware, so only the absolute minimum required processing is done for each request, this includes CB and other features
- Introduced a new in-memory distributed rate limiter, this removes the dependency on redis and makes performance much smoother, the DRL will measure load on each node and modify rate limits accordingly (so for example, on two nodes, the rate limit must be split between them), depending on the way the load is being distributed, one node may be getting less traffic than the others, the trate limiter will attempt to compensate for this. Load information is broadcast via redis pub/sub every 5s, this can be changed in tyk.conf. it is possible to use the old rate limiter too, simply ensure that `enable_redis_rolling_limiter` is set to true.
- Analytics writer now uses a managed pool, this mean a smoother performance curve under very high load (2k req p/s)
- All config settings can now be overriden with an environmnt variable, env variables must start with TYK_GW and must use the configuration object names specified in the `config.go`, NOT in the JSON file
- Implemented a cache mechanism for APIs that use the CP (CoProcess) feature, see "ID extractor".
- Session lifetime can be set globally (and forced, with a flag), add `"global_session_lifetime": 10` to your `tyk.conf`, where `10` is the session lifetime value you want to use. To force this value across all the APIs and override the per-API session lifetime, add `"force_global_session_lifetime": true` to your `tyk.conf`.
- Added (experimental, beta) LetsEncrypt support, the gateway will cache domain data as it sees it and synchronise / cache ssl certificates in Redis, to enable simply set `"http_server_options.use_ssl_le": true`
- Fixed a bug in which HMAC signatures generated in some libraries where URL-encoded cahracters result in a lower-cased octet pair instead of upper-cased (Golang / Java Default) caused valid HMAC strings to fail. We now check for this after an intiial failure just in case.
- Adding an `auth` or `post_auth` folder to a middleware api-id folder will let you add custom auth middleware and post-auth middleware that uses the JSVM
- Adding JSVM middleware for post key auth and auth can now also be done in the api definition itself
- Generate a key using:

```
# private key
openssl genrsa -out privkey.pem 2048

# public key
openssl rsa -in privkey.pem -pubout -out pubkey.pem
```


# v2.2

- Added the option to set the listen path (defaults to binding to all addresses)
- Fixed URL Rewriter to better handle query strings
- Added XML transform support for requests and responses, simply set the data type to `xml` int he transforms section and create your template the same way you would for JSON.

### XML transform demo

For this XML:

```
    <?xml version="1.0" encoding="utf-8"?>
    <servers version="1">
        <server>
            <serverName>Shanghai_VPN</serverName>
            <serverIP>127.0.0.1</serverIP>
        </server>
        <server>
            <serverName>Beijing_VPN</serverName>
            <serverIP>127.0.0.2</serverIP>
        </server>
    </servers>
```

And this Template:

```
    {
    {{range $x, $s := .servers.server}}    "{{$s.serverName}}": "{{$s.serverIP}}"{{if not $x}},{{end}}
    {{end}}
    }
```

You get this output:


```
    {
        "Shanghai_VPN": "127.0.0.1",
        "Beijing_VPN": "127.0.0.2"

    }
```

- Added request method transform: This is very simple at the moment, and only chagnes the type of method, it does not data massaging, to enaqble, add to your extended paths:

    method_transforms: [
            {
              path: "post",
              method: "GET",
              to_method: "POST"
            }
    ],

- Out of the box, tyk will ship with HA settings enabled where possible (this means using the new non-transactional rate limiter)
- Added a new concept called "Partitioned Policies", with policies that are partitioned, only sections of the policy will be applied to the underlying token so that tokens can be generated with a dynamic ACL, but still subscribe to a fixed quota and rate limit level. THIS MEANS THAT THE TOKEN MUST HAVE A FULL SET OF ACL RULES AND QUOTAS BEFORE USING AND PARTITIONED POLICIES ARE NOT SUITABLE FOR PORTAL USE.

### To set up a partitioned policy

Add the following section to the policy object:

    "partitions": {
        "quota": false,
        "rate_limit": false,
        "acl": false
    }

Then set the partitions that you want to overwrite to "true", the partitions that are marked as true will then be applied to the token instead of the full policy.

- Added context variable support, this middleware will extract the path, the path parts (break on `/`), and try to pull all form-related data (url-form-encoded or query string params) and put them into a context variable that is available to other middleware. Currently this is only integrated with the body transform middleware as `_tyk_context`. To enable set `"enable_context_vars": true` in the API Definition. Transform sample:

Path: {{._tyk_context.path}}

    Path Elements:
    {{ range $i, $v := ._tyk_context.path_parts }}
    --> {{$v}}
    {{ end }}

    Form/QueryString Data: {{._tyk_context.request_data}}
    Token: {{._tyk_context.token}}

- Context variables also available in headers using `$tyk_context.` namespace
- WARNING: POTENTIALLY BREAKING CHANGE: Flush interval is now in milliseconds, not seconds, before upgrading, if you are using flush interval, make sure that the value has been updated.
- Context variables also available in URL rewriter
- Added Websockets support (beta), websockets can now be proxied like a regular HTP request, tyk will detect the upgrade and initiate a proxy to the upstream websocket host. This can be TLS enabled and Tyk can proxy over HTTPS -> WSS upstream.
- Websockets execute at the end of the middleware chain, so all the benefits of CB and auth middleware can be enabled (within the limits of the WebSockets protocol)
- No analytics are gatthered for these requests, but rate limiting, quotas and auth will work fully for initial connection requsts (e.g . to prevent connection flooding)

# v2.1

- Fixed bug in contralised JWT secrets where OrgID was not set on internal token
- OAuth Clients are now fully editable (you can set the clientID and secret at creation time)
- OAuth client now support adding a matched Policy ID, if key_rules are not included when the tokens are authorized, the policy ID will be used as the baseline of the stored token - this is useful in cases where a third-party IDP provide clients and they must be matched to specific policies. THis also means you no longer nee to add key_rules to your oauth authorize callbacks, making the process more streamlined and standards-based.
- JWT Now suports a matched client: It is now possible to have a JWT contain a client ID (azp claim) and a base identity field (e.g. sub), Tyk will use the policy applied to the client on the base identity of the token, enabling matched clients in JWTs.

### For example:

- Developer registers a client app with your IDP
- You create a custom API token in Tyk that matches the client ID (This custom token *Must* use a policy)
- This custom token now represents this client application within Tyk - it is not the same as a registered OAuth client, this token only acts as a proxy key
- Set up your API with the `jwt_client_base_field` (the claim in the JWT that representsthe client ID - typically `azp`) and `jwt_identity_base_field` (the claim that represents the users identity - e.g. `sub`), do *not* use the `jwt_policy_field_name`, as this will alter the flow of the validation
- Generate a JWT that has these claims filled in, make sure the client ID in the `azp` field is the same as the one you have added to Tyk in step 1
- Create a request to Tyk

### What happens:

- Tyk will validate the JWT
- Tyk will extract the client ID fro the token, and fetch the token that you created, it will then check the policy
- Tyk will then fetch the underlying users identity and generate a hash to represent them locally
- Tyk will generate an internal token based on the identity and the policy from the Client ID going forward

- Added support for key aliases, when adding a token, you can now add an alias to the token, this will appear in analytics when viewing on a per-key basis, can be helpful for degugging problem users when using a hashed key set.

- Added OpenID Connect Token validation (OIDC ID Tokens) - this is similar to the JWT support but specific to OpenID Connect standard.

- OpenID Connect tokens can be rate-limited per client (so the same user comming via different clients can have different rate limits): in the open ID options, set `"segregate_by_client": true`

### Enabling OpenID Connect

**Set up your API Definition**

```
use_openid: true,
  openid_options: {
    providers: [
      {
        issuer: "accounts.google.com",
        client_ids: {
          NDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t: "571f84c430c55e4d45000002"
        }
      }
    ]
  },
```

**Options**

`openid_options.providers`

An array of supported providers

`openid_options.providers.issuer`

The name of the issuing entity, e.g. google acocunts

`openid_options.providers.client_ids`

A map of `base64(clientID):PolicyID`

This map will assign a policy already stored in Tyk to a client ID, this will cause Tyk to apply this policy to the underlying ientity of the uer (i.e. generate an internal token that represents the User that holds the token).

Why Base64? We require base64 encoded client IDs to ensure cross-compatability with document stores

What happens:

- Tyk will validate the JWT according to the OpenID Spec:

	1. Is the token a valid jwt?
	2. Is the token issued by a known OP?
	3. Is the token issued for a known client?
	4. Is the token valid at the time ('not use before' and 'expire at' claims)?
	5. Is the token signed accordingly?

- Tyk will then check the API definition for a supported Client/Policy under the issuing IDP
- This policy will then be used as a template for a new internal token that represents this user (so we can apply the policy across logins)
- The internal token is generated off of the OpenID connect User ID claim
- The request is then passed through to the rest of the Tyk validation chain

- Tyk Dashboard will now respect internal policy IDs (id instead of _id) for a policy object allowing for fixed-policy IDs across installations.
    - To enable, add `allow_explicit_policy_id: true` to your configuration file under the `policies` section
    - To enable compatibility in the dashboard, add `allow_explicit_policy_id: true` to the root of your dashboard conf
- Fixed policy bug where a policy would not corectly overwrite a token's access rights with the correct metadata, causing it to not be editable later.
- Black / White / Ignore / Transform and Injec lists are now matched on a lowercase version of the inbound path, so match patterns must be lowercase otherwise they will be ignored.
- New Response middleware to force target_url replacements in return headers such as "Link", and "Location" which tend to be set upstream by the service with incorrect values (real values)

    "response_processors": [
        {
            "name": "header_transform",
            "options": {
                "rev_proxy_header_cleanup": {
                    "headers": ["Link", "Location"],
                    "target_host": "http://TykHost:TykPort"
                }
            }
        }
    ]


# v2.0

- Limited multi-target support on a per-version basis: simply add "override_target": "http://domain.com" to the version section in your API Definition. Round Robin LB and Servie Discovery are *not* supported.
- Centralised JWT keys are now supported, adding `jwt_source` to an API definition will enable a central cert to validate all incoming tokens.
- `jwt_source` can either be a base64 encoded valid RSA/HMAC key OR a JWK URL, if it is a JWK URL then the `kid` must match the one in the JWK
- Centralised JWT keys need a `jwt_identity_base_field` that basically identifies the user in the Claims of the JWT, this will fallback to `sub` if not found. This field forms the basis of a new "virtual" token that gets used after validation, it means policy attributes are carried forward through Tyk for attribution purposes.
- Centralised JWT keys also need a `jwt_policy_field_name` which sets the policy to apply to the "virtual" key
- JWT header can now support "Bearer xxxx" style auth headers
- HMAC authentication now supports an alternate header (`x-aux-date`) for clients that do not provide a date header, this header is checked *first* before reverting to the `Date` field
- Added capability to preserve host header, if `proxy.preserve_host_header` is set to true in an API definition then the host header in the outbound request is retained to be the inbound hostname of the proxy.
- Added more default tags for better segmentation: key-{key-id}, org-{org-id} and api-{apiid} can now be used as tags to lock down the analytics filter in the dashboard.
- HMAC support re-written and updated to the latest spec
- HMAC: `request-target` now supported
- HMAC: `headers` signature field is now supported (this means `Digest` can be included)
- Purger has been removed from core completely (replaced by Pump)
- More tracing and more logging has been put in place, especially around API operations for easy tracing
- Hot reloads (redis based), will not reset the muxer if no specs are returned (mproves stability if a data source goes down or fails)
- REMOVED: MongoDB poller
- REMOVED: MongoDB Policy poller
- ADDED: Service-based API Definition loader (dashboard)
- ADDED: Service-based Policy loader (dashboard)
- To configure for API Defs:

	"use_db_app_configs": true,
    "db_app_conf_options": {
        "connection_string": "http://dashboard_host:port",
        "node_is_segmented": false,
        "tags": []
    },

- To configure for Policies:

	"policies": {
    	"policy_source": "service",
        "policy_connection_string": "http://dashboard_host:port"
    },

- Tyk nodes now register with a dashboard to be assigned an ID based on the licenses available.
- X-Forwarded For now used to log IP addresses in event log
- Analytics now records IP Address (OR X-F-F)
- Analytics now records GeoIP data, to enable add (DB is MaxMind):

	```
	"enable_geo_ip": true,
    "geo_ip_db_path": "./GeoLite2-City.mmdb"
    ```

- Analytics GeoIP DB can be replaced on disk, it will cleanly auto-reload every hour
- Detail logging can now be activated on an organisation basis, setting `enforce_org_data_detail_logging` in the tyk.conf will enforce it (quotas must also be enforced for this to work), then setting `enable_detail_recording` in the org session object will enable or disable the logging method
- Centralised JWTs add a `TykJWTSessionID` to the session meta data on create to enable upstream hosts to work with the internalised token should things need changing
- New System Events handler, works with existing event handlers, configure add to tyk.conf:

```
"event_handlers": {
    "events": {
        "TokenCreated": [
            {
                "handler_name": "eh_log_handler",
                "handler_meta": {
                    "prefix": "[TEST API EVENT]"
                }
            }
        ],
        "TokenUpdated": [
            {
                "handler_name": "eh_log_handler",
                "handler_meta": {
                    "prefix": "[TEST API EVENT]"
                }
            }
        ]

    }
}
```

- Nw Multi-DC / segregated environment / single dashboard support added for API and Keyspace propagation
- Added new rate limit handler that is non-transactional, this can be enabled by setting `enable_non_transactional_rate_limiter` to true, this can provide exceptional performance improvements
- Added option to enable or disable the sentinel-based rate-limiter, sentinel-based rate limiter provides a smoother performance curve as rate-limit calculations happen off-thread, but a stricter time-out based cooldown for clients. Disabling the sentinel based limiter will make rate-limit calculations happen on-thread and therefore offers staggered cool-down and a smoother rate-limit experience for the client and similar performance as the sentinel-based limiter. This is disabled by default. To enable, set `enable_sentinel_rate_limiter` to `true`

# 1.9.1.1

- Added CIDR Support (thanks @iwat)
- Updated to build with Go 1.5.3 to address [CVE-2015-8618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8618)

# 1.9.1

- Added new feature: Detailed logging, enable by setting `analytics_config.enable_detailed_recording` to true, two new fields will be added to analytics data: rawRequest and rawResponse, these will be in wire format and are *NOT* anonymised. This adds additional processing complexity to request throughput so could degrade performance.
- Added a check for connection failures
- Updating a key with a quota reset set to true will also remove any rate limit sentinels
- URL Rewrites and cache interactions now work properly, although you need to define the cached entry as the rewritten pattern in a seperate entry.
- Org quotas monitors now only fire when the renewal is in the future, not the past.
- Fixed bug where quotas would not reset (regression introduced by switch to Redis Cluster), Tyk will automaticall correct quota entries taht are incorrect.
- Using golang builtins for time checking

# 1.9

- Gateway Mongo Driver updated to be compatible with MongoDB v3.0
- Fixed OAuth client listings with redis cluster
- Some latency improvements
- Key detection now checks a local in-memory cache before reaching out to Redis, keys are cached for 10 seconds, with a 5 second purge rate (so a maximum key existence of 15s). Policies will still tkake instant effect on keys
- key session cache is configurable, set `local_session_cache.cached_session_timeout` (default 10) and `local_session_cache.cached_session_eviction` (default 5) to the cache ttl and eviction scan times
- key session cache can be disabled: `local_session_cache.disable_cached_session_state`
- Test update to reduce number of errors, cleaner output
- Healthcheck data now stored in a sorted set, much cleaner and faster, now works with redis cluster!
- Bug fixed: Empty or invalid listen path no longer crashes proxy
- Bug fixed: Basic Auth (and Oauth BA) passwords are now hashed, this is backward compatible, plaintext passwords will still work
- OAuth access token expiry can now be set (in seconds) in the `tyk.conf` file using `oauth_token_expire:3600`
- Proxy now records accurate status codes for upstream requests for better error reporting
- Added refresh token invalidation API: `DELETE /tyk/oauth/refresh/{key}?api_id={api_id}`
- Global header injection now works, can be enabled on a per-version basis by adding `global_headers:{"header_name": "header value"}` to the version object in the API Definition, global injections also supports key metadata variables.
- Global header deletion now works: add `"global_headers_remove":["header_name", "header_name"] to your version object
- Added request size limiter, request size limiter middleware will insist on content-length to be set, and check first against content-length value, and then actual request size value. To implement, add this to your version info:

	"size_limits": [
	    {
	      "path": "widget/id",
	      "method": "PUT",
	      "size_limit": 25
	    }
	  ]

- Request size limits can also be enforced globally, these are checked first, to implement, add `"global_size_limit": 30` to your version data.
- Adding a `key_expires_in: seconds` property to a policy definition will cause any key that is created or added using this policy to have a finite lifetime, it will expire in `now()+key_expiry` seconds, handy for free trials
- Dependency update (logrus)
- Added support for JSON Web Token (JWT), currently HMAC Signing and RSA Public/Private key signing is supported. To enable JWT on an API, add `"enable_jwt": true,` to your API Definition. Then set your tokens up with these new fields when you create them:

	```
	"jwt_data": {
		"secret": "Secret"
	}
	```

- HMAC JWT secrets can be any string, but the secret is shared. RSA secrets must be a PEM encoded PKCS1 or PKCS8 RSA private key, these can be generated on a linux box using:

	> openssl genrsa -out key.rsa
	> openssl rsa -in key.rsa -pubout > key.rsa.pub

- Tyk JWT's MUST use the "kid" header attribute, as this is the internal access token (when creating a key) that is used to set the rate limits, policies and quotas for the user. The benefit here is that if RSA is used, then al that is stored in a Tyk installatino that uses hashed keys is the hashed ID of the end user and their public key, and so very secure.
- Fixed OAuth Password flow bug where a user could generate more than one token for the same API

- Added realtime uptime monitoring, uptime monitoring means you can create a series of check requests for your upstream hosts (they do not need to be the same as the APIs being managed), and have the gateway poll them for uptime, if a host goes down (non-200 code or TCP Error) then an Event is fired (`HostDown`), when it goes back up again another event is fired (`HostUp`), this can be combined with the webhook feature for realtime alerts
- Realtime monitoring also records statistics to the database so they can be analyised or graphed later
- Real time monitoring can also be hooked into the load balancer to have the load balancer skip bad hosts for dynamic configuration
- When hosts go up and down, sentinels are activated in Redis so all nodes in a Tyk cluster can benefit
- Only one Tyk node will ever do the polling, they use a rudimentary capture-the-flag redis key to identify who is the uptime tester
- Monitoring can also be disabled if you want a non-active node to manage uptime tests and analytics purging
- The uptime test list can be refreshed live by hot-reloading Tyk
- Active monitoring can be used together with Circuit breaker to have the circuit breaker manage failing methods, while the uptime test can take a whole host offline if it becomes unresponsive
- To configure uptime tests, in your tyk.conf:

	```
	"uptime_tests": {
        "disable": false, // disable uptime tests on the node completely
        "config": {
            "enable_uptime_analytics": true,
            "failure_trigger_sample_size": 1,
            "time_wait": 5,
            "checker_pool_size": 50
        }
    }
    ```

- Check lists usually sit with API configurations, so in your API Definition:

	```
	uptime_tests: {
	    check_list: [
	      {
	        "url": "http://google.com:3000/"
	      },
	      {
	        "url": "http://posttestserver.com/post.php?dir=tyk-checker-target-test&beep=boop",
	        "method": "POST",
	        "headers": {
	          "this": "that",
	          "more": "beans"
	        },
	        "body": "VEhJUyBJUyBBIEJPRFkgT0JKRUNUIFRFWFQNCg0KTW9yZSBzdHVmZiBoZXJl"
	      }
	    ]
	  },
	  ```

- The body is base64 encoded in the second example, the first example will perform a simple GET, NOTE: using the simplified form will not enforce a timeout, while the more verbose form will fail with a 500ms timeout.
- Uptime tests can be configured from a service (e.g. etcd or consul), simply set this up in the API Definition (this is etcd):

	```
	"uptime_tests": {
	    "check_list": [],
	    "config": {
	      "recheck_wait": 12,
	      "service_discovery": {
	        "use_discovery_service": true,
	        "query_endpoint": "http://127.0.0.1:4001/v2/keys/uptimeTest",
	        "data_path": "node.value"
	      }
	    }
	},
	```
- Uptime tests by service discovery will load initially from the endpoint, it will not re-poll the service until it detects an error, at which point it will schedule a reload of the endpoint data. If used in conjunction with upstream target service discovery it enables dynamic reconfiguring (and monitoring) of services.
- The document that Tyk requires is a JSON string encoded version of the `check_list` parameter of the `uptime_tests` field, for etcd:

	curl -L http://127.0.0.1:4001/v2/keys/uptimeTest -XPUT -d value='[{"url": "http://domain.com:3000/"}]'

- Fixed a bug where incorrect version data would be recorded in analytics for APis that use the first URL parameter as the version (domain.com/v1/blah)
- Added domain name support (removes requirement for host manager). The main Tyk instance can have a hostname (e.g. apis.domain.com), and API Definitions can support their own domains (e.g. mycoolservice.com), multiple API definitions can have the same domain name so long as their listen_paths do not clash (so you can API 1 on mycoolservice.com/api1 and API 2 on mycoolservice.com/api2 if you set the listen_path for API 1 and API2 respectively.)
- Domains are loaded dynamically and strictly matched, so if calls for a listen path or API ID on the main tyk hostname will not work for APIs that have custom domain names set, this means services can be nicely segregated.
- If the hostname is blank, then the router is open and anything will be matched (if you are using host manager, this is the option you want as it leaves domain routing up to NginX downstream)
- Set up the main tyk instance hostname by adding `"hostname": "domain.com"` to the config
- Enable custom api-specific domains by setting `enable_custome_domains` in the tyk.conf to true
- Make an API use a custom domain by adding a `domain` element to the root object
- Custom domains will work with your SSL certs
- Refactored API loader so that it used pointers all the way down, this lessens the amount of data that needs copying in RAM (will only really affect systems running 500+ APIs)
- JSVM is now disabled by default, if you are not using JS middleware, you can reduce Tyk footprint significantly by not enabling it. To re-enable set `"enable_jsvm": true` in tyk.conf
- Fixed CORS so that if OPTIONS passthrough is enabled an upstream server can handle all pre-flight requests without any Tyk middleware intervening
- Dashboard config requires a home_dir field in order to work outside of it's home dir
- Added option to segragate control API from front-end, set `enable_api_segregation` to true and then add the hostname to `control_api_hostname`

# 1.8.3.2

- Enabled password grant type in OAuth:

	- Create new client
	- Create a basic auth key for each user
	- Set the `allowed_access_types` array to include `password`
	- Generate a valid access request with the client_id:client_secret as a Basic auth header and the u/p in the form of the body.
	- POST to: `/oauth/token/` endpoint on your OAuth-enabled API
	- If successfull, the user will get:

	```
	{"access_token":"4i0VmSYMQ2iN7ivX0LaYBw","expires_in":3600,"refresh_token":"B_99PjEmQquufNWs8QYbow","token_type":"bearer"}
	```



- Enable streaming endpoints by setting a flush interval in your tyk.conf ile:

    "http_server_options": {
        "flush_interval": 1
    }



- Experimental Redis Cluster support, in tyk.conf:

	"storage": {
        "type": "redis",
        "enable_cluster": true,
        "hosts" : {
            "server1": "6379",
            "server2": "6379",
            "server23: "6379",
        },
        "username": "",
        "password": "",
        "database": 0,
        "optimisation_max_idle": 100
    },

# v1.8.3

- SSL Now supported, add this to your `tyk.conf`:

	```
	"http_server_options": {
        "use_ssl": true,
        "server_name": "www.banana.com",
        "min_version": "1.2",
        "certificates": [
            {
                "domain_name": "*",
                "cert_file": "new.cert.cert",
                "key_file": "new.cert.key"
            }
        ]
    },
    ```

# v1.8

- Security option added for shared nodes: Set `disable_virtual_path_blobs=true` to stop virtual paths from loading blob fields
- Added session meta data variables to transform middleware:

	You can reference session metadata attached to a key in the header injector using:

	```
	$tyk_meta.KEY_NAME
	```

	And in the body transform template through:

	```
	._tyk_meta.KEYNAME
	```

	You must enable sesison parsing in the TemplateData of the body tranform entry though by adding:

	```
	"enable_session": true
	```

	To the path entry

- Added CORS support, add a CORS section to your API definition:

	 ```
	 CORS: {
	    enable: false,
	    allowed_origins: [
	      "http://foo.com"
	    ]
	 },
	 ```

- Full CORS Options are:

	```
	CORS struct {
		Enable             bool     `bson:"enable" json:"enable"`
		AllowedOrigins     []string `bson:"allowed_origins" json:"allowed_origins"`
		AllowedMethods     []string `bson:"allowed_methods" json:"allowed_methods"`
		AllowedHeaders     []string `bson:"allowed_headers" json:"allowed_headers"`
		ExposedHeaders     []string `bson:"exposed_headers" json:"exposed_headers"`
		AllowCredentials   bool     `bson:"allow_credentials" json:"allow_credentials"`
		MaxAge             int      `bson:"max_age" json:"max_age"`
		OptionsPassthrough bool     `bson:"options_pasthrough" json:"options_pasthrough"`
		Debug              bool     `bson:"debug" json:"debug"`
	} `bson:"CORS" json:"CORS"`
	```

- Fixed cache bug
- When using node segments, tags will be transferred into analytics data as well as any token-level tags, so for example, you could tag each node independently, and then view the trafic that went through those nodes by ID or group them in aggregate
- You can now segment gateways that use a DB-backed configurations for example if you vae APIs in different regions, or only wish to service a segment of your APIs (e.g. "Health APIs", "Finance APIs"). So you can have a centralised API registry using the dashboard, and then Tag APIs according to their segment(s), then configure your Tyk nodes to only load those API endpoints, so node 1 may only serve health APIs, while node 2 might serve a mixture and node 3 will serve only finance APIs. To enable, simply configure your node and add to `tyk.conf` and `host_manager.conf` (if using):

	"db_app_conf_options": {
        "node_is_segmented": false,
        "tags": ["test2"]
    }

- You will need to add a `tags: []` sectino to your API definition in the DB to enable this feature, or set it in the dashboard.
- Dynamic endpoints support response middleware
- Dynamic endpoints support caching
- Dynamic endpoints also count towards analytics
- JSVM now has access to a `TykBatchRequest` function to make batch requests in virtual paths. Use case: Create a virtual endpoint that interacts with multiple upstream APIs, gathers the data, processes the aggregates somehow and returns them as a single body. This can then be cached to save on load.
- Added virtual path support, you can now have a JS Function respond to a request, makes mocking MUCh more flexible, TODO: expose batch methods to JSVM. To activate, add to extended paths:

	```
	virtual: [
        {
          response_function_name: "thisTest",
          function_source_type: "file",
          function_source_uri: "middleware/testVirtual.js",
          path: "virtualtest",
          method: "GET",
          use_session: true
        }
    ]
    ```

- Virtual endpoint functions are pretty clean:

	```
	function thisTest(request, session, config) {
		log("Virtual Test running")

		log("Request Body: ")
		log(request.Body)

		log("Session: ")
		log(session)

		log("Config:")
		log(config)

		log("param-1:")
		log(request.Params["param1"])

		var responseObject = {
			Body: "THIS IS A  VIRTUAL RESPONSE"
			Headers: {
				"test": "virtual",
				"test-2": "virtual"
			},
			Code: 200
		}

		return TykJsResponse(responseObject, session.meta_data)

	}
	log("Virtual Test initialised")
	```

- Added refresh tests for OAuth
- URL Rewrite in place, you can specify URLs to rewrite in the `extended_paths` seciton f the API Definition like so:

	```
	"url_rewrites": [
        {
          "path": "virtual/{wildcard1}/{wildcard2}",
          "method": "GET",
          "match_pattern": "virtual/(.*)/(\d+)",
          "rewrite_to": "new-path/id/$2/something/$1"
        }
      ]
    ```

- You can now add a `"tags":["tag1, "tag2", tag3"] field to token and policy definitions, these tags are transferred through to the analytics record when recorded. They will also be available to dynamic middleware. This means there is more flexibility with key ownership and reporting by segment.`
- Cleaned up server output, use `--debug` to see more detailed debug data. Keeps log size down
- TCP Errors now actually raise an error
- Added circuit breaker as a path-based option. To enable, add a new sectino to your versions `extended_paths` list:

	circuit_breakers: [
        {
          path: "get",
          method: "GET",
          threshold_percent: 0.5,
          samples: 5,
          return_to_service_after: 60
        }
      ]

Circuit breakers are individual on a singlie host, they do not centralise or pool back-end data, this is for speed. This means that in a load balanced environment where multiple Tyk nodes are used, some traffic can spill through as other nodes reach the sampling rate limit. This is for pure speed, adding a redis counter layer or data-store on every request to a servcie would jsut add latency.

Circuit breakers use a thresh-old-breaker pattern, so of sample size x if y% requests fail, trip the breaker.

The circuit breaker works across hosts (i.e. if you have multiple targets for an API, the samnple is across *all* upstream requests)

When a circuit breaker trips, it will fire and event: `BreakerTriggered` which you can define actions for in the `event_handlers` section:

	```
	event_handlers: {
	    events: {
	      BreakerTriggered: [
	        {
	          handler_name: "eh_log_handler",
	          handler_meta: {
	            prefix: "LOG-HANDLER-PREFIX"
	          }
	        },
	        {
	          handler_name: "eh_web_hook_handler",
	          handler_meta: {
	            method: "POST",
	            target_path: "http://posttestserver.com/post.php?dir=tyk-event-test",
	            template_path: "templates/breaker_webhook.json",
	            header_map: {
	              "X-Tyk-Test-Header": "Tyk v1.BANANA"
	            },
	            event_timeout: 10
	          }
	        }
	      ]
	    }
	  },
	```

Status codes are:

	```
	// BreakerTripped is sent when a breaker trips
	BreakerTripped = 0

	// BreakerReset is sent when a breaker resets
	BreakerReset = 1
	```

- Added round-robin load balancing support, to enable, set up in the API Definition under the `proxy` section:

	...
	"enable_load_balancing": true,
	"target_list": [
		"http://server1",
		"http://server2",
		"http://server3"
	],
	...

- Added REST-based Servcie discovery for both single and load balanced entries (tested with etcd, but anything that returns JSON should work), to enable add a service discovery section to your Proxy section:

	```
	// Solo
	service_discovery : {
      use_discovery_service: true,
      query_endpoint: "http://127.0.0.1:4001/v2/keys/services/single",
      use_nested_query: true,
      parent_data_path: "node.value",
      data_path: "hostname",
      port_data_path: "port",
      use_target_list: false,
      cache_timeout: 10
    },


	// With LB
	"enable_load_balancing": true,
	service_discovery: {
      use_discovery_service: true,
      query_endpoint: "http://127.0.0.1:4001/v2/keys/services/multiobj",
      use_nested_query: true,
      parent_data_path: "node.value",
      data_path: "array.hostname",
      port_data_path: "array.port",
      use_target_list: true,
      cache_timeout: 10
    },
    ```

- For service discovery, multiple assumptions are made:
	- The response data is in JSON
	- The response data can have a nested value set that will be an encoded JSON string, e.g. from etcd:

	```
	$ curl -L http://127.0.0.1:4001/v2/keys/services/solo

	{
	    "action": "get",
	    "node": {
	        "key": "/services/single",
	        "value": "{\"hostname\": \"http://httpbin.org\", \"port\": \"80\"}",
	        "modifiedIndex": 6,
	        "createdIndex": 6
	    }
	}
	```

	```
	$ curl -L http://127.0.0.1:4001/v2/keys/services/multiobj

	{
	    "action": "get",
	    "node": {
	        "key": "/services/multiobj",
	        "value": "{\"array\":[{\"hostname\": \"http://httpbin.org\", \"port\": \"80\"},{\"hostname\": \"http://httpbin.org\", \"port\": \"80\"}]}",
	        "modifiedIndex": 9,
	        "createdIndex": 9
	    }
	}
	```

	Here the key value is actually an encoded JSON string, which needs to be decoded separately to get to the data.

	- In some cases port data will be separate from host data, if you specify a `port_data_path`, the values will be zipped together and concatenated into a valid proxy string.
	- If use_target_list is enabled, then enable_load_balancing msut also be enabled, as Tyk will treat the list as a target list.
	- The nested data object in a service registry key MUST be a JSON Object, **not just an Array**.


- Fixed bug where version parameter on POST requests would empty request body, streamlined request copies in general.
- it is now possible to use JSVM middleware on Open (Keyless) APIs
- It is now possible to configure the timeout parameters around the http server in the tyk.conf file:

	"http_server_options": {
        "override_defaults": true,
        "read_timeout": 10,
        "write_timeout": 10
    }

 - It is now possible to set hard timeouts on a path-by-path basis, e.g. if you have a long-running microservice, but do not want to hold up a dependent client should a query take too long, you can enforce a timeout for that path so the requesting client is not held up forever (or maange it's own timeout). To do so, add this to the extended_paths section of your APi definition:

	 ...
	 extended_paths: {
          ...
          transform_response_headers: [],
          hard_timeouts: [
            {
              path: "delay/5",
              method: "GET",
              timeout: 3
            }
          ]
    }
    ...


# v1.7
- Open APIs now support caching, body transforms and header transforms
- Added RPC storage backend for cloud-based suport. RPC server is built in vayala/gorpc, signature for the methods that need to be provideda are in the rpc_storage_handler.go file (see the dispatcher).
- Added `oauth_refresh_token_expire` setting in configuration, allows for customisation of refresh token expiry
- Changed refresh token expiry to be 14 days by default
- Basic swagger file supoprt in command line, use `--import-swagger=petstore.json` to import a swagger definition, will create a Whitelisted API.
- Created quota monitoring for orgs and user keys, uses a webhook. To configure update tyk.conf to include the gloabl check rate and target data:

	"monitor": {
        "enable_trigger_monitors": false,
        "configuration": {
        "method": "POST",
            "target_path": "http://posttestserver.com/post.php?dir=tyk-monitor-test",
            "template_path": "templates/monitor_template.json",
            "header_map": {"x-tyk-monitor-secret": "12345"},
            "event_timeout": 10
        },
        "global_trigger_limit": 80.0,
        "monitor_user_keys": false,
        "monitor_org_keys": true
    }

- It is also possible to add custom rate monitors on a per-key basis, SessionObject has been updated to include a "monitor" section which lets you define custom limits to trigger a quota event, add this to your key objects:

	"monitor": {
        "trigger_limits": [80.0, 60.0, 50.0]
    }

- If a cusotm limit is the same as a global oe the event will only fire once. The output will look like this:

	{
	    "event": "TriggerExceeded",
	    "message": "Quota trigger reached",
	    "org": "53ac07777cbb8c2d53000002",
	    "key": "53ac07777cbb8c2d53000002c74f43ddd714489c73ea5c3fc83a6b1e",
	    "trigger_limit": "80",
	}

- Added response body transforms (JSON only), uses the same syntax as regular transforms, must be placed into `transform_response" list and the trasnformer must be registered under `response_transforms`.
	{
      name: "response_body_transform",
      options: {}
    }

- Added Response middleware chain and interface to handle response middleware. Response middleware must be declared under `response_processors` otherwise it is not loaded. Speciying options under the extended paths section will not be enough to enable response processors

	{
      name: "header_injector",
      options: {
      	"add_headers": {"name": "value"},
      	"remove_headers": ["name"]
  	  }
    }

- Added repsonse header injection (uses the same code as the regular injector), add your path definitions to the `extended_paths.transform_response_headers` filed, uses the same syntx as header injection
- Added SupressDefaultOrgStore - uses a default redis connection to handle unfound Org lookups
- Added support for Sentry DSN
- Modification: Analyitcs purger (redis) now uses redis lists, much cleaner, and purge is a transaction which means multiple gateways can purge at the same time safely without risk of duplication
- Added `enforce_org_data_age` config parameter that allows for setting the expireAt in seconds for analytics data on an organisation level. (Requires the addition of a `data_expires` filed in the Session object that is larger than 0)

# v1.6
- Added LDAP StorageHandler, enables basic key lookups from an LDAP service
- Added Policies feature, you can now define key policies for keys you generate:
    - Create a policies/policies.json file
    - Set the appropriate arguments in tyk.conf file:

		```
		"policies": {
			"policy_source": "file",
			"policy_record_name": "./policies/policies.json"
		}
		```

	- Create a policy, they look like this:

		```
		{
			"default": {
				"rate": 1000,
				"per": 1,
				"quota_max": 100,
				"quota_renewal_rate": 60,
				"access_rights": {
					"41433797848f41a558c1573d3e55a410": {
						"api_name": "My API",
						"api_id": "41433797848f41a558c1573d3e55a410",
						"versions": [
							"Default"
						]
					}
				},
				"org_id": "54de205930c55e15bd000001",
				"hmac_enabled": false
			}
		}
		```

	- Add a `apply_policy_id` field to your Session object when you create a key with your policy ID (in this case the ID is `default`)
	- Reload Tyk
	- Policies will be applied to Keys when they are loaded form Redis, and the updated i nRedis so they can be ueried if necessary

- Policies can invalidate whole keysets by copying over the `InActive` field, set this to true in a policy and all keys that have the policy set will be refused access.

- Added granular path white-list: It is now possible to define at the key level what access permissions a key has, this is a white-list of regex keys and apply to a whole API definition. Granular permissions are applied *after* version-based (global) ones in the api-definition. These granular permissions take the form a new field in the access rights field in either a policy definition or a session object in the new `allowed_urls` field:

	```
	{
		"default": {
			"rate": 1000,
			"per": 1,
			"quota_max": 100,
			"quota_renewal_rate": 60,
			"access_rights": {
				"41433797848f41a558c1573d3e55a410": {
					"api_name": "My API",
					"api_id": "41433797848f41a558c1573d3e55a410",
					"versions": [
						"Default"
					],
					"allowed_urls": [
						{
							"url": "/resource/(.*),
							"methods": ["GET", "POST"]
						}
					]
				}
			},
			"org_id": "54de205930c55e15bd000001",
			"hmac_enabled": false
		}
	}
	```

- Added `hash_keys` config option. Setting this to `true` willc ause Tyk to store all keys in Redis in a hashed representation. This will also obfuscate keys in analytics data, using the hashed representation instead. Webhooks will cotuniue to make the full API key available. This change is not backwards compatible if enabled on an existing installation.
- Added `cache_options.enable_upstream_cache_control` flag to API definitions
    - Upstream cache control is exclusive, caching must be enabled on the API, and the path to listen for upstream headers *must be defined in the `extended_paths` section*, otherwise the middleware will not activate for the path
    - Modified caching middleware to listen for two response headers: `x-tyk-cache-action-set` and `x-tyk-cache-action-set-ttl`.
    - If an upstream application replies with the header `x-tyk-cache-action-set` set to `1` (or anything non empty), and upstream control is enabled. Tyk will cache the response.
    - If the upstream application sets `x-tyk-cache-action-set-ttl` to a numeric value, and upstream control is enabled, the cached object will be created for whatever number of seconds this value is set to.
- Added `auth.use_param` option to API Definitions, set to tru if you want Tyk to check for the API Token in the request parameters instead of the header, it will look for the value set in `auth.auth_header_name` and is *case sensitive*
- Host manager now supports Portal NginX tempalte maangement, will generate portal configuration files for NginX on load for each organisation in DB
- Host manager will now gracefully attempt reconnect if Redis goes down
- *Tyk will now reload on notifications from Redis* (dashboard signal) for cluster reloads (see below), new option in config `SuppressRedisSignalReload` will suppress this behaviour (for example, if you are still using old host manager)
- Added new group reload endpoint (for management via LB), sending a GET to /tyk/reload/group will now send a pub/sub notification via Redis which will cause all listening nodes to reload gracefully.
- Host manager can now be set to manage Tyk or not, this means host manager can be deployed alongside NGinX without managing Tyk, and Tyk nodes reloading on their own using redis pub/sub
- Rate limiter now uses a rolling window, makes gaming the limiter by staddling the TTL harder

# v1.5
- Added caching middleware
- Added optimisation settings for out-of-thread session updates and redis idle pool connections
- Added cache option to cache safe requests, means individual paths need not be defined, but all GET, OPTIONS and HEAD requests will be cached
- Added request transformation middleware, thus far only tested with JSON input. Add a golanfg template to the extended path config like so:

        "transform": [
            {
                "path": "/",
                "template_data": {
                    "template_mode": "file",
                    "template_source": "./templates/transform_test.tmpl"
                }
            }
        ]

- Added header transformation middleware, simple implementation, but will delte and add headers before request is outbound:

        "transform_headers": [
            {
                "delete_headers": ["Content-Type", "authorization"],
                "add_headers": {"x-tyk-test-inject": "new-value"},
                "path": "/post"
            }
        ]


# v1.4

- Added expiry TTL to `tykcommon`, data expiry headers will be added to all analytics records, set `expire_analytics_after` to `0` to have data live indefinetely (currently 100 years), set to anything above zero for data in MongoDB to be removed after x seconds. **requirement**: You must create an expiry TTL index on the tyk_analytics collection manually (http://docs.mongodb.org/manual/tutorial/expire-data/). If you do not wish mongo to manage data warehousing at all, simply do not create the index.
- Added a JS Virtual Machine so dynamic JS middleware can be run PRE and POST middleware chain
- Added a global JS VM
- Added an `eh_dynamic_handler` event handler type that runs JS event handlers
- Added Session management API and HttpRequest API to event handler JSVM.
- Added JS samples
- Fixed a bug where requests that happened at identical times could influence the quota wrongly
- Changed default quota behaviour: On create or update, key quotas are reset. *unless* a new param `?suppress_reset=1` accompanies the REST request. This way a key can be updated and have the quote in Redis reset to Max, OR it can be edited without affecting the quota
- Rate limiter now uses new Redis based rate limiting pattern
- Added a `?reset_quota=1` parameter check to `/tyk/orgs/key` endpoint so that quotas can be reset for organisation-wide locks
- Organisations can now have quotas
- Keys and organisations can be made inactive without deleting


# v1.3:

- It is now possible to set IP's that shouldn't be tracked by analytics by setting the `ignored_ips` flag in the config file (e.g. for health checks)
- Many core middleware configs moved into tyk common, tyk common can now be cross-seeded into other apps if necessary and is go gettable.
- Added a healthcheck function, calling `GET /tyk/health` with an `api_id` param, and the `X-Tyk-Authorization` header will return upstream latency average, requests per second, throttles per second, quota violations per second and key failure events per second. Can be easily extended to add more data.
- Tyk now reports quote status in response headers (Issue #27)
- Calling `/{api-id}/tyk/rate-limits` with an authorised header will return the rate limit for the current user without affecting them. Fixes issue #27
- Extended path listing (issue #16) now enabled, legacy paths will still work. You can now create an extended path set which supports forced replies (for mocking) as well as limiting by method, so `GET /widget/1234` will work and `POST /windget/1234` will not.
- You can now import API Blueprint files (JSON format) as new version definitions for your API, this includes mocking out responses. Blueprints can be added to existing API's as new versions or generate independent API definitions.
  - Create a new definition from blueprint: `./tyk --import-blueprint=blueprint.json --create-api --org-id=<id> --upstream-target="http://widgets.com/api/"`
  - Add a version to a definition: `./tyk --import-blueprint=blueprint.json --for-api=<api_id> --as-version="2.0"`
  - Create a mock for either: use the `--as-mock` parameter.
- More tests, many many more tests
