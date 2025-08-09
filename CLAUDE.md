# Tyk Gateway Development Guide

This document contains helpful information for developing and debugging Tyk Gateway features.

## Debugging Tips

### Enable Debug Logging

To see detailed debug output when running tests or the gateway:

```bash
# For tests
TYK_LOGLEVEL=debug go test -v -run TestName ./gateway

# Note: It's TYK_LOGLEVEL not TYK_LOG_LEVEL
```

### Common Test Patterns

When writing integration tests, use the test framework properly:

```go
// Create an API with authentication
ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
    spec.Name = "Test API"
    spec.APIID = "test-api"
    spec.OrgID = "default"
    spec.UseKeylessAccess = false
    spec.Auth.AuthHeaderName = "Authorization"
    spec.Proxy = apidef.ProxyConfig{
        ListenPath:      "/api/",
        TargetURL:       "http://upstream.example.com/",
        StripListenPath: true,  // Important: strips the listen path from upstream requests
    }
    spec.EnableContextVars = true
})

// Create a session with metadata
_, apiKey := ts.CreateSession(func(s *user.SessionState) {
    s.MetaData = map[string]interface{}{
        "key": "value",
    }
    s.AccessRights = map[string]user.AccessDefinition{
        "test-api": {APIID: "test-api"},
    }
})

// Run a test request
resp, err := ts.Run(t, test.TestCase{
    Path:    "/api/endpoint",
    Method:  http.MethodGet,
    Headers: map[string]string{"Authorization": apiKey},
    Code:    http.StatusOK,
})

// Parse response
var result map[string]interface{}
err = json.NewDecoder(resp.Body).Decode(&result)
```

## Dynamic Upstream URLs Feature

### Overview

The dynamic upstream URLs feature allows you to use variables in the `target_url` configuration of your APIs. This enables routing requests to different upstream servers based on session metadata, request context, or external configuration.

### Configuration

Enable dynamic variables in your API definition:

```json
{
  "name": "My API",
  "api_id": "my-api",
  "proxy": {
    "listen_path": "/api/",
    "target_url": "http://$tyk_meta.upstream_host:$tyk_meta.port/",
    "strip_listen_path": true
  },
  "enable_context_vars": true
}
```

### Supported Variables

#### Session Metadata Variables (`$tyk_meta.*`)
Access any field from the user session's metadata:
- `$tyk_meta.upstream_host` - Custom upstream host
- `$tyk_meta.region` - User's region
- `$tyk_meta.environment` - Target environment
- `$tyk_meta.tenant_id` - Tenant identifier

#### Request Context Variables (`$tyk_context.*`)
Access request-specific information:
- `$tyk_context.headers_X_Custom_Header` - Any request header (replace `-` with `_`)
- `$tyk_context.remote_addr` - Client IP address
- `$tyk_context.path` - Request path
- `$tyk_context.request_id` - Unique request ID

#### Secret Variables
- `$secret_env.*` - Environment variables (must be prefixed with `TYK_SECRET_`)
- `$secret_vault.*` - HashiCorp Vault secrets
- `$secret_consul.*` - Consul KV store values
- `$secret_conf.*` - Configuration secrets

### Use Cases

#### Multi-Tenant Routing
Route requests to tenant-specific backends:
```json
{
  "target_url": "http://$tyk_meta.tenant_id.service.internal/"
}
```

#### Regional Routing
Route users to their nearest datacenter:
```json
{
  "target_url": "http://$tyk_meta.region.api.example.com/"
}
```

#### Environment-Based Routing
Route to different environments based on user permissions:
```json
{
  "target_url": "http://$tyk_meta.environment.internal/$tyk_meta.service/"
}
```

#### Header-Based Routing
Route based on request headers:
```json
{
  "target_url": "http://$tyk_context.headers_X_Backend_Host/"
}
```

### Implementation Details

The feature is implemented in `gateway/reverse_proxy.go` in the director function. Key points:

1. Variables are processed after target URL selection (load balancing or static)
2. The existing `ReplaceTykVariables` function handles the substitution
3. Connection pooling works automatically - Go's `http.Transport` maintains separate pools per host
4. Works with both load balancing and service discovery

### Debugging Dynamic URLs

To debug variable replacement:

1. Enable debug logging to see the original and processed URLs:
```bash
TYK_LOGLEVEL=debug go test -v -run YourTest ./gateway
```

2. Look for log messages like:
```
level=debug msg="Processing dynamic variables in upstream URL" original_url="http://$tyk_meta.upstream_host/" processed_url="http://127.0.0.1:8080/"
```

3. Common issues:
   - **Empty scheme error**: Make sure the processed URL includes the protocol (http:// or https://)
   - **404 errors**: Check if `StripListenPath` is set correctly
   - **Variable not replaced**: Ensure `EnableContextVars` is true and the variable exists in metadata

### Testing Dynamic URLs

Example test setup:

```go
func TestDynamicUpstream(t *testing.T) {
    ts := StartTest(nil)
    defer ts.Close()

    // Create upstream server
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
    }))
    defer upstream.Close()
    
    upstreamURL, _ := url.Parse(upstream.URL)

    // Create API with dynamic URL
    ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
        spec.APIID = "dynamic-api"
        spec.Proxy = apidef.ProxyConfig{
            ListenPath: "/api/",
            TargetURL:  "http://$tyk_meta.upstream_host/",
        }
        spec.EnableContextVars = true
    })

    // Create session with upstream host
    _, key := ts.CreateSession(func(s *user.SessionState) {
        s.MetaData = map[string]interface{}{
            "upstream_host": upstreamURL.Host,
        }
        s.AccessRights = map[string]user.AccessDefinition{
            "dynamic-api": {APIID: "dynamic-api"},
        }
    })

    // Test the request
    resp, err := ts.Run(t, test.TestCase{
        Path:    "/api/test",
        Headers: map[string]string{"Authorization": key},
        Code:    http.StatusOK,
    })
}
```

## Performance Considerations

### Connection Pooling

Dynamic URLs with different hosts automatically use separate connection pools in Go's HTTP client. The transport configuration in Tyk handles this:

- `MaxIdleConns`: Total idle connections across all hosts
- `MaxIdleConnsPerHost`: Idle connections per individual host (default: 100)
- `IdleConnTimeout`: How long connections stay in the pool (90 seconds)

### Variable Processing Performance

- Variables are only processed when `EnableContextVars` is true
- Regex patterns are pre-compiled for efficiency
- Variable substitution happens once per request in the director function
- Consider caching implications when using dynamic URLs with many different values

## Common Pitfalls

1. **URL Parsing Errors**: Ensure your dynamic URLs form valid URLs after substitution
2. **Missing Variables**: Variables that don't exist won't be replaced (literal string remains)
3. **Path Joining**: Be careful with trailing slashes when using variables in paths
4. **Load Balancing**: Each target in the load balancing list can contain variables
5. **Service Discovery**: The `query_endpoint` can also contain variables

## Related Files

- `gateway/reverse_proxy.go` - Main reverse proxy implementation
- `gateway/mw_url_rewrite.go` - Variable replacement logic
- `gateway/mw_context_vars.go` - Context variable population
- `apidef/api_definitions.go` - API configuration structures
- `user/session.go` - Session state and metadata

## Running Tests

```bash
# Run all dynamic URL tests
go test -v -run TestDynamicUpstreamURL_ ./gateway

# Run with debug output
TYK_LOGLEVEL=debug go test -v -run TestDynamicUpstreamURL_ ./gateway

# Run specific test
go test -v -run TestDynamicUpstreamURL_Integration ./gateway -count=1
```

## Contributing

When adding new features that involve URL processing:

1. Ensure backward compatibility
2. Add comprehensive tests including error cases
3. Document any new variables or configuration options
4. Consider connection pooling implications
5. Test with load balancing and service discovery enabled