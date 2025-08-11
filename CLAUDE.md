# Claude Code Testing Guide for Tyk Gateway

This document contains tips, tricks, and patterns discovered while working with Tyk Gateway tests, specifically when fixing the `TestEndpointRL_NonTransactional` test.

## Testing Patterns and Best Practices

### 1. Port Conflicts in Tests

**Problem**: Tests failing with "address already in use" for port 16500
- The test HTTP server uses a hardcoded port `127.0.0.1:16500` in `testutil.go`
- When running multiple tests concurrently or if cleanup fails, this causes conflicts

**Common Error**:
```
testServer.ListenAndServe() err: listen tcp 127.0.0.1:16500: bind: address already in use
```

**Current Solutions**:
- The main gateway uses dynamic ports (you'll see random ports like 54498, 56170 in test output)
- The test HTTP server still uses hardcoded port 16500
- Tests generally work around this by proper cleanup in `defer ts.Close()`

**Best Practice**: Always use `defer ts.Close()` immediately after `StartTest()`

### 2. API Configuration for Tests

#### Listen Paths and Proxying

When creating APIs with custom listen paths, you need to set `StripListenPath = true`:

```go
api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
    spec.Proxy.ListenPath = "/api-1/"
    spec.Proxy.TargetURL = TestHttpAny
    spec.Proxy.StripListenPath = true  // Critical!
    spec.UseKeylessAccess = false
})[0]
```

**Why**: Without `StripListenPath = true`, a request to `/api-1/get` would be proxied to `TestHttpAny + "/api-1/get"`, but the test server only handles `/get`.

#### Test Server Endpoints

The test HTTP server (defined in `testutil.go`) handles these endpoints:
- `/get` (GET only)
- `/post` (POST only) 
- `/errors/{status}` (any status code)
- `/{rest:.*}` (catch-all dynamic handler)

**Tip**: Use `/errors/200` for testing as it's a reliable endpoint that returns the status you specify.

### 3. Endpoint Rate Limiting Tests

#### Session Creation Pattern

For endpoint rate limiting, create sessions with endpoint-specific limits:

```go
_, key := ts.CreateSession(func(s *user.SessionState) {
    s.AccessRights = map[string]user.AccessDefinition{
        api.APIID: {
            APIID:   api.APIID,
            APIName: api.Name,
            Endpoints: user.Endpoints{
                {
                    Path: "/get",
                    Methods: []user.EndpointMethod{
                        {Name: "GET", Limit: user.RateLimit{Rate: 3, Per: 60}},
                    },
                },
            },
        },
    }
})
```

#### Testing Rate Limits

- **Reset Strategy**: Create new sessions for different test scenarios to reset rate limit counters
- **Verification**: Test both success cases (within limits) and failure cases (exceeding limits)
- **Separation**: Different endpoints have independent rate limit counters

### 4. Hash Key Configuration Testing

When testing different hash configurations:

```go
tcs := []struct {
    name     string
    hashKey  bool
    hashAlgo string
}{
    {name: "hash_key_false", hashKey: false},
    {name: "hash_key_true_murmur64", hashKey: true, hashAlgo: "murmur64"},
    // ... more configurations
}

// Apply configuration
globalConf := ts.Gw.GetConfig()
globalConf.HashKeys = tc.hashKey
globalConf.HashKeyFunction = tc.hashAlgo
ts.Gw.SetConfig(globalConf)
```

### 5. Rate Limiter Configuration

#### NonTransactional Rate Limiter

```go
globalConf.RateLimit.EnableNonTransactionalRateLimiter = true
```

#### Other Rate Limiters

```go
// Redis
globalConf.RateLimit.EnableRedisRollingLimiter = true

// Sentinel  
globalConf.RateLimit.EnableSentinelRateLimiter = true

// DRL
globalConf.RateLimit.DRLEnableSentinelRateLimiter = true
```

### 6. Test Organization

#### Subtest Pattern

Use subtests to organize complex test scenarios:

```go
t.Run("scenario_name", func(t *testing.T) {
    // Scenario-specific setup
    
    // Tests for this scenario
    _, _ = ts.Run(t, []test.TestCase{
        {Path: "/get", Headers: authHeader, Code: http.StatusOK},
        {Path: "/get", Headers: authHeader, Code: http.StatusTooManyRequests},
    }...)
})
```

#### Test Case Pattern

```go
_, _ = ts.Run(t, []test.TestCase{
    {
        Path:    "/api-endpoint",
        Method:  "GET",  // Optional, defaults to GET
        Headers: authHeader,
        Code:    http.StatusOK,
    },
}...)
```

### 7. Common Test Issues and Solutions

#### Skipped Tests

If you see `t.Skip()` in tests, it's often due to:
- Race conditions with shared resources
- Port conflicts
- Cleanup interference (like `DeleteAllKeys`)

**Solution**: Instead of skipping, isolate the test or fix the underlying issue.

#### 404 vs 500 Errors

- **404 Not Found**: Usually means the test server doesn't handle that path
- **500 Internal Server Error**: Often indicates upstream server issues or port conflicts

#### DeleteAllKeys Issues

The `providerCustomRatelimitKey` function was skipped because:
```go
t.Skip() // DeleteAllKeys interferes with other tests.
```

This suggests `DeleteAllKeys()` has race conditions when tests run concurrently.

### 8. Debugging Test Failures

#### Log Analysis

Look for these patterns in test output:
- Port numbers in URLs (e.g., `http://127.0.0.1:54498`) - these should be dynamic
- Error messages about "address already in use"
- 404 vs 500 status codes in failures

#### Common Fixes

1. **Port conflicts**: Ensure proper test cleanup with `defer ts.Close()`
2. **Missing routes**: Use endpoints that exist on test server (`/get`, `/post`, `/errors/200`)
3. **Rate limit isolation**: Create separate sessions for different test scenarios
4. **Configuration**: Apply rate limiter config before creating APIs and sessions

### 9. Enterprise Edition Tests

Tests tagged with `--tags ee` require enterprise features:
```bash
go test --timeout 30s --tags ee --run TestEndpointRL_NonTransactional
```

### 10. Performance Considerations

- Use appropriate timeouts (`--timeout 30s`)
- Minimize session creation in loops
- Use realistic rate limits for faster test execution
- Consider test isolation to prevent interference

## Useful Commands

```bash
# Run specific test with enterprise tags
go test --timeout 30s --tags ee --run TestEndpointRL_NonTransactional

# Run with specific subtest
go test --timeout 30s --tags ee --run TestEndpointRL_NonTransactional/hash_key_false

# Find tests containing specific patterns
rg -n "TestEndpointRL" --type go

# Find files with port conflicts
rg -n "16500" --type go

# Find rate limiter configurations
rg -n "EnableNonTransactionalRateLimiter" --type go
```

## Summary

The key to successful Tyk Gateway testing is understanding:
1. Port management and conflicts
2. Proper API configuration with `StripListenPath`
3. Session isolation for rate limiting tests
4. Test server endpoint availability
5. Enterprise feature requirements

When encountering "There was a problem proxying the request" with 500 errors, first check for port conflicts and ensure proper test cleanup.