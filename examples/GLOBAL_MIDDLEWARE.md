# Global Middleware System

The Global Middleware system allows you to apply middleware across all APIs managed by the Tyk Gateway, with fine-grained control over which APIs are affected.

## Overview

Global middleware operates in two phases:
- **Pre-phase**: Executed before API-specific middleware
- **Post-phase**: Executed after API-specific middleware

## Configuration

Global middleware is configured in the main gateway configuration file under the `global_middleware` section:

```json
{
  "global_middleware": {
    "pre": [
      {
        "name": "middleware_name",
        "enabled": true,
        "priority": 10,
        "include_apis": ["api1", "api2"],
        "exclude_apis": ["internal-api"],
        "config": {
          "key": "value"
        }
      }
    ],
    "post": [
      // Post-phase middleware configurations
    ]
  }
}
```

### Configuration Options

- **name**: The name of the middleware to use (must be registered)
- **enabled**: Whether this middleware is active
- **priority**: Execution order (lower numbers execute first)
- **include_apis**: If specified, middleware only applies to these API IDs
- **exclude_apis**: API IDs that should skip this middleware
- **config**: Middleware-specific configuration

## Built-in Global Middleware

### Traffic Mirror (`traffic_mirror`)

Mirrors incoming requests to external destinations for analytics, testing, or monitoring.

#### Configuration:
```json
{
  "name": "traffic_mirror",
  "config": {
    "sample_rate": 0.1,
    "async": true,
    "timeout": 5,
    "headers": {
      "X-Mirror-Source": "tyk-gateway"
    },
    "destinations": [
      {
        "url": "https://analytics.example.com/webhook",
        "timeout": 10,
        "headers": {
          "Authorization": "Bearer token"
        }
      }
    ]
  }
}
```

#### Options:
- **sample_rate**: Percentage of requests to mirror (0.0-1.0)
- **async**: Whether to mirror asynchronously
- **timeout**: Default timeout for mirror requests (seconds)
- **headers**: Global headers to add to all mirrored requests
- **destinations**: Array of mirror destinations

#### Destination Options:
- **url**: Target URL for mirrored requests
- **timeout**: Per-destination timeout override
- **headers**: Destination-specific headers

### Global Headers (`global_headers`)

Adds, modifies, or removes headers globally.

#### Configuration:
```json
{
  "name": "global_headers",
  "config": {
    "request_headers": {
      "X-Gateway-Version": "5.0"
    },
    "response_headers": {
      "X-Powered-By": "Tyk"
    },
    "remove_request_headers": ["X-Internal-Token"],
    "remove_response_headers": ["Server"]
  }
}
```

#### Options:
- **request_headers**: Headers to add to incoming requests
- **response_headers**: Headers to add to outgoing responses
- **remove_request_headers**: Request headers to remove
- **remove_response_headers**: Response headers to remove

## API Inclusion/Exclusion

You can control which APIs are affected by global middleware:

1. **No restrictions**: Leave both `include_apis` and `exclude_apis` empty
2. **Whitelist approach**: Specify `include_apis` to only affect listed APIs
3. **Blacklist approach**: Specify `exclude_apis` to skip listed APIs
4. **Combined**: Use both for complex scenarios (exclude takes precedence)

## Execution Order

1. Global pre-middleware (sorted by priority)
2. API-specific middleware
3. Backend request
4. API-specific response middleware
5. Global post-middleware (sorted by priority)

## Development Guide

### Creating Custom Global Middleware

1. Implement the middleware struct:

```go
type MyGlobalMiddleware struct {
    *GlobalBaseMiddleware
    Config map[string]interface{}
}

func (m *MyGlobalMiddleware) Name() string {
    return "MyGlobalMiddleware"
}

func (m *MyGlobalMiddleware) EnabledForSpec() bool {
    return true
}

func (m *MyGlobalMiddleware) Init() {
    m.GlobalBaseMiddleware.BaseMiddleware.Init()
    // Initialize your middleware
}

func (m *MyGlobalMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
    // Process the request
    return nil, http.StatusOK
}
```

2. Register the middleware in `initGlobalMiddlewareRegistry()`:

```go
gw.GlobalMiddlewareRegistry.Register("my_middleware", func(base *GlobalBaseMiddleware, config map[string]interface{}) TykMiddleware {
    return &MyGlobalMiddleware{
        GlobalBaseMiddleware: base,
        Config:               config,
    }
})
```

### Configuration Helper Methods

The `GlobalBaseMiddleware` provides helper methods for configuration access:

- `GetConfigString(key string) string`
- `GetConfigBool(key string) bool`
- `GetConfigInt(key string) int`
- `GetConfigFloat(key string) float64`
- `GetConfigStringSlice(key string) []string`
- `GetConfigMap(key string) map[string]interface{}`

## Testing

See `global_middleware_test.go` and `global_traffic_mirror_test.go` for examples of testing global middleware.

## Performance Considerations

1. **Async Processing**: Use `async: true` for non-critical operations like analytics
2. **Sampling**: Use `sample_rate` to reduce load for high-volume mirroring
3. **Timeouts**: Set appropriate timeouts to prevent hanging requests
4. **Resource Cleanup**: Implement proper resource cleanup in middleware

## Security Notes

1. Mirrored requests include all headers and body content
2. Be careful with sensitive data in mirror destinations
3. Use HTTPS for mirror endpoints when possible
4. Implement proper authentication for mirror endpoints