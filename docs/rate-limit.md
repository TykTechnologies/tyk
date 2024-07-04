# Rate Limiting

## Rate Limiting Redis Keys

If we backtrace a rate limiting decision, then we have to start in
`internal/rate`, namely the Prefix function:

```
func LimiterKey(currentSession *user.SessionState, rateScope string, key string, useCustomKey bool) string {
	if !useCustomKey && !currentSession.KeyHashEmpty() {
		return Prefix(LimiterKeyPrefix, rateScope, currentSession.KeyHash())
	}

	return Prefix(LimiterKeyPrefix, rateScope, key)
```

This constructs a key with a `rate-limit` prefix. The key then includes
`rateScope`, and the KeyHash or the custom key if set. This ends up
either as `rate-limit-<rateScope>-<key>` or just `rate-limit-<key>` if
scope is empty.

To facilitate per-endpoint rate limit settings and enforce them
individually, the rateScope should be set to something that identifies
the endpoint. An endpoint is identified by method and path, the logical
way forward is to hash those two values into `rateScope`.

## SessionLimiter ForwardMessage function

The ForwardMessage function recieves:

- rateLimitKey
- quotaKey
- enableRL (to remove? we have apispec)
- enableQ (to remove? we have apispec)

If a quotaKey is provided, then:

- useCustomKey is set to true, rateLimitKey is used instead of the session KeyHash.

The value for `rateScope` is derived from session access rights
(AllowanceScope). If no access rights exist for the API, an error is
returned and the request is blocked.

The function is invoked from:

- OrganisationMonitor
- RateLimitAndQuotaCheck (if we have auth)
- RateLimitForAPI

## OrganisationMonitor

- Passes OrgID as `rateLimitKey`, empty quota key
- Runs before several middlewares before RL MW is reached
- ExperimentalProcessOrgOffThread

Various code smells in the area, notably:

- ExperimentalProcessOrgOffThread
- k.Spec.OrgSessionManager (should have cache implementation if anything)
- cache is spaghetti code, rate limit and quota concerns

## RateLimitAndQuotaCheck

- `rate_limit_pattern` in session.MetaData is used, after replacing tyk vars
  - this is used as a quotaKey as well, triggering different behaviour
  - Passed into SessionLimiterForwardMessage as `rateLimitKey`
- multi-purpose - also does quota (shared responsibility)

SECURITY note: tyk variables contain secrets, we don't want to enable configuring secrets as redis key values

## RateLimitForAPI

- Creates a session using GlobalRate (`global_rate_limit`) as the defined session rate
- Rate limiter key name is `apilimiter-{orgID}-{APIID}`
- Passed into SessionLimiter.ForwardMessage as `rateLimitKey`

The session is created once per middleware chain (on start or reload).
Refactoring note: should have implemented Init().

# Implementation notes

- SessionLimiter: enableRL / enableQ should be computed from *APISpec
- RateLimitAndQuotaCheck should likely be two middlewares, one for quota one for RL
- Session cache: https://github.com/TykTechnologies/tyk/pull/6154/files
- Can improve performance with: https://github.com/huandu/go-clone
