# DEV
- Added Response middleware chain and interface to handle response middleware. Response middleware must be declared under `response_processors` otherwise it is not loaded. Speciying options under the extended paths section will not be enough to enable response processors
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