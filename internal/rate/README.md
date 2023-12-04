# Tests

Rate limiter function tests:

| Tests                                  | Coverage       |
| -------------------------------------- | -------------- |
| Unit tests (`task unit`)               | 100% coverage  |
| Integration tests (`task integration`) | 94.7% coverage |

task: Available tasks for this project:

* cover:                 Show source coverage      (aliases: coverage, cov, uncover)
* integration:           Run integration tests
* unit:                  Run unit tests
* install:uncover:       Install uncover

Running `task cover` prints the coverage report for both test types.

# Rate limiting window functions

Our current implementation of rate limiting window functions returns the
result of a ZRANGE command, that retrieves all the rate limiter members
from the set.

Breaking down the Set function:

- Set(..., keyName string, per int64, value_override string, pipeline bool) ([]string, error) {

This function is hit every time that the rate limiter would log a hit.
Typically this happens with the following values:

- `keyName`: `apilimiter-{orgID}{apiID}` - the redis key for the rate limit ZSET

A timestamp argument passed (usually `time.Now`) and the `per` value calculate
the period value for the previous `per` window (time - per * second). This
value is used to remove items from the set that are older than the previous
period.

The first command it invokes is the cleanup of any keys from the ZSET, that
are older than the previous period end.

```
ZRemRangeByScore(ctx, keyName, "-inf", period)
```

The second command it invokes is a `ZRANGE 0, -1`, which returns a list
of keys inside the ZSET that are relevant for the rolling window interval.

The expected values of a zset are a value of redis.Z:

- Member: string (1701694602668369097 - now.UnixNano)
- Score: float64 (now.UnixNano)

The member key is essentially unique, and the keys score is the always
increasing time value, which enables removal of old entries.

Finally, the request updates the TTL on the set key, making it live as long
as there have been any requests to it inside the specified time window. If
no requests are made, the key set gets deleted by redis after this period.

```
ZRemRangeByScore(ctx, keyName, "-inf", period)
ZRange(ctx, keyName, 0, -1)
ZAdd(ctx, keyName, element)
Expire(ctx, keyName, expire)
```

## Notes

The ZSET stores a list of requests, which is memory intensive for a
rolling window implementation. Whatever requests are made within a `per`
period are stored in the set, and expired entries are purged out for any
per value.

To optimize the redis interactions, it would be possible to:

- Use a ZCount instead of ZRemRangeByScore + ZRange (-1 ops/request, significantly smaller redis response)
- Run ZRemRangeByScore cleanup in background (every X seconds period instead of per-request)
- Expire could only be used in key creation/seen, rather than every request

HealthChecks are the only consumer of the range scores, and yet the
rolling window functions all issue ZRemRangeByScore / ZRange on a
significant dataset size under high traffic.

## Usage

```
./gateway/api_healthcheck.go:
	// reportHealthValue is a shortcut we can use throughout the app to push a health check value
	// func reportHealthValue(spec *APISpec, counter HealthPrefix, value string) {
	go h.storage.SetRollingWindow(searchStr, h.Gw.GetConfig().HealthCheck.HealthCheckValueTimeout, value, false)
./gateway/api_healthcheck.go:
	// getAvgCount implements, used in ApiHealthValues()
	count, _ := h.storage.SetRollingWindow(searchStr, h.Gw.GetConfig().HealthCheck.HealthCheckValueTimeout, "-1", false)
./gateway/api_healthcheck.go:
	// Used in ApiHealthValues (the health check endpoint)
	_, vals := h.storage.SetRollingWindow(searchStr, h.Gw.GetConfig().HealthCheck.HealthCheckValueTimeout, "-1", false)
```

This is an example where the values returned from Set are being used to
calculate the average request latency within the window. For this case,
`ZRangeByScore` would be needed to retrieve the details.

The last two occurences of Set usage here could have been `Get`.
HealthChecks track several `APIID.<area>` keys only to track the latency
over the API. This also exposes the implementation detail that in this case
we're using a different value for `{apiID}.Request`;

```
handler_success.go:	reportHealthValue(s.Spec, RequestLog, strconv.FormatInt(timing.Total, 10))
```

In these, `timing.Total` is passed as a custom value.

```
coprocess.go:		reportHealthValue(m.Spec, KeyFailure, "1")
handler_error.go:	reportHealthValue(e.Spec, BlockedRequestLog, "-1")
mw_api_rate_limit.go:	reportHealthValue(k.Spec, Throttle, "-1")
mw_auth_key.go:	reportHealthValue(k.Spec, KeyFailure, "1")
mw_basic_auth.go:	reportHealthValue(k.Spec, KeyFailure, "-1")
mw_ip_blacklist.go:	reportHealthValue(i.Spec, KeyFailure, "-1")
mw_ip_whitelist.go:	reportHealthValue(i.Spec, KeyFailure, "-1")
mw_jwt.go:	reportHealthValue(k.Spec, KeyFailure, "1")
mw_key_expired_check.go:		reportHealthValue(k.Spec, KeyFailure, "-1")
mw_key_expired_check.go:	reportHealthValue(k.Spec, KeyFailure, "-1")
mw_oauth2_key_exists.go:		reportHealthValue(k.Spec, KeyFailure, "-1")
mw_openid.go:	reportHealthValue(k.Spec, KeyFailure, "1")
mw_rate_limiting.go:	reportHealthValue(k.Spec, Throttle, "-1")
mw_rate_limiting.go:	reportHealthValue(k.Spec, QuotaViolation, "-1")
```

A particular detail is handling for `!= "-1"` in reportHealthValue.

```
if value != "-1" {
	// need to ensure uniqueness
	now_string := strconv.Itoa(int(time.Now().UnixNano()))
	value = now_string + "." + value
}
```

Previously: string (1701694602668369097 - now.UnixNano)
Here:       string (1701694602668369097.<timing.Total>)

This value is being relied upon in ApiHealthValues to produce a single
value, the average request rate.


```
./gateway/session_manager.go:
	ratePerPeriodNow, _ = store.SetRollingWindow(rateLimiterKey, int64(per), "-1", pipeline)
```

Session manager only uses the number of requests that have been issued
within a per duration window. It doesn't read in the returned data from
ZRANGE, but only the count. This is what is used in rate limiting
middleware.

```
./gateway/rpc_storage_handler.go:
	return r.SetRollingWindow(keyName, per, val, false)
```

RPC has an implementation of SetRollingWindow, but not Get; It only
passes `keyName` and `per`. The parameters `val` and `pipeline` are
unused in the function. It uses recursion and has a danger of an infinite
loop. The RPC implementation only returns the count as well.


# Get

Invoking Get would perform the cleanup of stale rolling window hashes, as it
also invokes the first two commands of Set: `ZREMRANGEBYSCORE` and `ZRANGE`.

It does not attempt to modify the TTL on the key, but will remove elements
outside of the rolling window interval on the key.

## Usage

The only place this is invoked is:

./gateway/session_manager.go:

```
ratePerPeriodNow, _ = store.GetRollingWindow(rateLimiterKey, int64(per), pipeline)
```

It's invoked if `dryRun bool` is true (a test only function path).
