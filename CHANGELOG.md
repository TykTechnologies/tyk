# Changes in dev version:

- It is now possible to set IP's that shouldn't be tracked by analytics by setting the `ignored_ips` flag in the config file (e.g. for health checks) 
- Many core middleware configs moved into tyk common, tyk common can now be cross-seeded into other apps if necessary and is go gettable.
- Added a healthcheck function, calling GET /tyk/health with an api_id param, and the tyk secret header will return upstream latency average, requests per second, throttles per second, quota violations per second and key failure events per second. Can be easily extended to add more data.
- Tyk now reports quote status in response headers (Issue #27)
- Calling /tyk/rate-limits with an authorised header will return the rate limit for the current user without affecting them. Fixes issue #27