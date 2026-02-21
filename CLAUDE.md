# Tyk Gateway Development Guide

This document provides essential information for developing, debugging, and testing Tyk Gateway features. It serves as a reference for AI assistants and developers working with the codebase.

## Project Overview

Tyk Gateway is a high-performance, open-source API Gateway written in Go. It provides features like authentication, rate limiting, analytics, and reverse proxy capabilities.

### Key Components

- **Gateway Core** (`gateway/`) - Main gateway logic including middleware, reverse proxy, and API management
- **API Definitions** (`apidef/`) - Structures and types for API configuration
- **User Management** (`user/`) - Session state, authentication, and authorization
- **Storage** (`storage/`) - Database and caching abstractions
- **Internal** (`internal/`) - Internal packages and utilities
- **Test Framework** (`test/`) - Testing utilities and helpers

## Development Environment Setup

### Build Commands

```bash
# Build the gateway
go build -o tyk ./gateway/

# Run tests for a specific package
go test -v ./gateway

# Run specific test
go test -v -run TestName ./gateway

# Run tests with race detection
go test -race -v ./gateway

# Generate mocks
go generate ./...
```

### Environment Variables

Important environment variables for development:

```bash
# Logging
TYK_LOGLEVEL=debug  # Options: debug, info, warn, error

# Database
TYK_DB_REDISHOST=localhost:6379
TYK_DB_REDISDATABASE=0

# Secrets (for dynamic variables)
TYK_SECRET_*  # Any env var prefixed with TYK_SECRET_ can be accessed as $secret_env.*
```

## Testing Best Practices

### Integration Test Framework

Tyk uses a comprehensive test framework for integration testing. Here's how to use it effectively:

```go
// Basic test structure
func TestFeature(t *testing.T) {
    // Start test server
    ts := StartTest(nil)
    defer ts.Close()

    // Create and load API definition
    ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
        spec.Name = "Test API"
        spec.APIID = "test-api"
        spec.OrgID = "default"
        spec.UseKeylessAccess = false
        spec.Auth.AuthHeaderName = "Authorization"
        spec.Proxy = apidef.ProxyConfig{
            ListenPath:      "/api/",
            TargetURL:       "http://upstream.example.com/",
            StripListenPath: true,  // Strips listen path from upstream requests
        }
    })

    // Create session with custom metadata
    _, apiKey := ts.CreateSession(func(s *user.SessionState) {
        s.MetaData = map[string]interface{}{
            "custom_field": "value",
        }
        s.AccessRights = map[string]user.AccessDefinition{
            "test-api": {APIID: "test-api"},
        }
    })

    // Make test request
    resp, err := ts.Run(t, test.TestCase{
        Path:    "/api/endpoint",
        Method:  http.MethodGet,
        Headers: map[string]string{"Authorization": apiKey},
        Code:    http.StatusOK,
    })
    require.NoError(t, err)

    // Parse and validate response
    var result map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&result)
    require.NoError(t, err)
}
```

### Creating Mock Upstream Servers

```go
// Create a mock upstream server
upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Validate request
    assert.Equal(t, "/expected-path", r.URL.Path)
    
    // Return response
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "ok",
        "path": r.URL.Path,
    })
}))
defer upstream.Close()
```

## Debugging Tips

### Enable Debug Logging

```bash
# For tests
TYK_LOGLEVEL=debug go test -v -run TestName ./gateway

# For running the gateway
TYK_LOGLEVEL=debug ./tyk

# Note: It's TYK_LOGLEVEL not TYK_LOG_LEVEL
```

### Common Debugging Patterns

1. **Request Flow Debugging**: Add debug logs in middleware to trace request flow
2. **Variable Inspection**: Use `fmt.Printf("%+v\n", variable)` for struct inspection
3. **HTTP Request/Response**: Use `httputil.DumpRequest` and `httputil.DumpResponse`
4. **Goroutine Leaks**: Use `go test -race` to detect race conditions

### Useful Debug Output Locations

- Request processing: `gateway/reverse_proxy.go` - Director function
- Middleware execution: `gateway/mw_*.go` files
- Authentication: `gateway/mw_auth_key.go`, `gateway/mw_jwt.go`
- Session management: `gateway/session_manager.go`

## Dynamic Variables System

Tyk supports dynamic variables that can be used in various configurations:

### Variable Types

1. **Session Metadata** (`$tyk_meta.*`) - From user session metadata
2. **Request Context** (`$tyk_context.*`) - From current request
3. **Secrets** (`$secret_env.*`, `$secret_vault.*`, `$secret_consul.*`, `$secret_conf.*`)
4. **Request Data** (`$tyk_context.request_data.*`) - From request body/params

### Variable Resolution

Variables are resolved by the `ReplaceTykVariables` function in `gateway/mw_url_rewrite.go`. To use variables:

1. Enable in API definition: `spec.EnableContextVars = true`
2. Use variable syntax: `$category.field_name`
3. Variables are replaced at runtime during request processing

### Common Use Cases

- Dynamic upstream routing based on user metadata
- Header-based routing
- Environment-specific configurations
- Multi-tenant architectures

## Architecture Patterns

### Middleware Chain

Tyk uses a middleware chain pattern. Middleware are executed in order:

1. **Pre-middleware** - Authentication, rate limiting, etc.
2. **Post-Auth middleware** - URL rewriting, transforms, etc.
3. **Reverse Proxy** - Forward request to upstream
4. **Response middleware** - Response transforms, caching

### Connection Pooling

Go's `http.Transport` handles connection pooling automatically:

- Separate pools per unique `(scheme, host, port)` tuple
- Configured in `gateway/reverse_proxy.go`
- Default settings: `MaxIdleConnsPerHost: 100`, `IdleConnTimeout: 90s`

### Load Balancing

Tyk supports round-robin load balancing:

```go
spec.Proxy.EnableLoadBalancing = true
spec.Proxy.Targets = []string{
    "http://upstream1.example.com",
    "http://upstream2.example.com",
}
```

## Common Pitfalls and Solutions

### 1. StripListenPath Issues

**Problem**: Upstream receives wrong path
**Solution**: Set `StripListenPath: true` in `ProxyConfig` to remove the listen path

### 2. Variable Not Replaced

**Problem**: Variables appear literally in requests
**Solution**: Ensure `EnableContextVars: true` and variable exists in context

### 3. Authentication Failures

**Problem**: 401 Unauthorized despite valid key
**Solution**: Check `Auth.AuthHeaderName` matches your header name

### 4. Test Compilation Errors

**Problem**: Package name conflicts (e.g., `user` variable vs `user` package)
**Solution**: Rename loop variables to avoid shadowing package names

### 5. URL Parsing Errors

**Problem**: "unsupported protocol scheme" errors
**Solution**: Ensure URLs include protocol (http:// or https://)

## Key Files Reference

### Core Gateway Files

- `gateway/reverse_proxy.go` - Main reverse proxy implementation
- `gateway/api_loader.go` - API definition loading and management
- `gateway/middleware.go` - Middleware chain management
- `gateway/session_manager.go` - Session and key management
- `gateway/server.go` - HTTP server setup and management

### Middleware Files

- `gateway/mw_auth_key.go` - API key authentication
- `gateway/mw_jwt.go` - JWT authentication
- `gateway/mw_rate_limit.go` - Rate limiting
- `gateway/mw_url_rewrite.go` - URL rewriting and variable replacement
- `gateway/mw_context_vars.go` - Context variable population
- `gateway/mw_transform*.go` - Request/response transformations

### Configuration Files

- `apidef/api_definitions.go` - API specification structures
- `config/config.go` - Gateway configuration
- `user/session.go` - Session state structures

### Test Utilities

- `test/test.go` - Main test framework
- `gateway/testutil.go` - Gateway-specific test helpers

## Testing Commands

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./gateway

# Run benchmarks
go test -bench=. ./gateway

# Run with verbose output and specific test
go test -v -run TestDynamicUpstream ./gateway

# Run with race detection
go test -race ./gateway

# Run tests multiple times (useful for flaky tests)
go test -count=10 -run TestName ./gateway
```

## Code Style Guidelines

1. **Follow Go conventions**: Use `gofmt` and `golint`
2. **Error handling**: Always check and handle errors appropriately
3. **Logging**: Use structured logging with appropriate levels
4. **Testing**: Write both unit and integration tests
5. **Documentation**: Add godoc comments for exported functions

## Contribution Checklist

When adding new features:

- [ ] Ensure backward compatibility
- [ ] Add comprehensive unit tests
- [ ] Add integration tests using the test framework
- [ ] Document configuration options
- [ ] Update relevant middleware if needed
- [ ] Consider performance implications
- [ ] Test with various authentication methods
- [ ] Test with load balancing enabled
- [ ] Verify connection pooling behavior
- [ ] Add debug logging for troubleshooting

## Getting Help

### Internal Documentation

- Check `docs/` directory for detailed documentation
- Review existing tests for usage examples
- Look at similar features for implementation patterns

### Debugging Resources

- Enable debug logging with `TYK_LOGLEVEL=debug`
- Use Go's built-in profiling tools (pprof)
- Check test output for detailed error messages
- Review git history for similar changes

## Performance Tips

1. **Connection Reuse**: Ensure proper connection pooling configuration
2. **Caching**: Use Redis for session storage and caching
3. **Middleware Order**: Place expensive middleware later in chain
4. **Logging Level**: Use appropriate log levels in production
5. **Resource Limits**: Configure appropriate timeouts and limits

## Security Considerations

1. **Never log sensitive data**: API keys, passwords, tokens
2. **Validate all inputs**: Especially in middleware
3. **Use secure defaults**: TLS, authentication required
4. **Rate limiting**: Always enable for production APIs
5. **Audit logging**: Enable for compliance requirements