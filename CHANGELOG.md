# DEV
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