# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tyk Gateway is an open-source, enterprise-ready API Gateway written in Go. It supports REST, GraphQL, TCP, and gRPC protocols and is designed for high performance.

## Build and Development Commands

The project uses both Makefile and Taskfile.yml (Task is preferred). Requires Go 1.23.10+.

### Essential Commands

```bash
# Setup and build
task setup              # Initial setup with dependencies and git hooks
task build              # Build the gateway (preferred over make build)
go build -tags "coprocess grpc goplugin" .  # Direct build with all features

# Testing
task test:integration   # Run integration tests with required services
go test ./...          # Run all unit tests
go test -run TestName ./gateway  # Run specific test

# Code quality
task lint              # Run all linters
task fmt               # Format code
task fmt:imports       # Format imports

# Development services
task services:up       # Start Redis and other test services
task services:down     # Stop test services

# Running the gateway
./tyk --conf tyk.conf  # Run with config file
```

### Build Tags

- `coprocess`: Enable coprocess support (Python, Lua)
- `grpc`: Enable gRPC support
- `goplugin`: Enable Go plugin support
- `ee`: Enable enterprise features (in ee/ folder)

## Architecture and Code Structure

### Core Components

- **Main Entry**: `main.go` → `gateway.Start()`
- **Gateway Package** (`gateway/`): Core functionality, middleware, proxy logic
- **API Definitions** (`apidef/`): API specifications, OAS support
- **Configuration** (`config/`): Config management and validation
- **Storage** (`storage/`): Redis and backend abstraction
- **Middleware**: `gateway/mw_*.go` files implement the middleware chain

### Key Patterns

1. **Middleware Chain**: All features implemented as middleware (`BaseMiddleware` interface)
2. **API Specifications**: APIs configured via `APISpec` struct or OpenAPI
3. **Storage Abstraction**: All persistent data through storage interface
4. **Plugin Architecture**: Supports Go, Python, Lua, gRPC, and JavaScript plugins

### Testing Patterns

```go
func TestFeature(t *testing.T) {
    ts := StartTest(nil)  // Start test server
    defer ts.Close()
    
    ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
        // Configure test API
        spec.Proxy.ListenPath = "/"
    })
    
    ts.Run(t, []test.TestCase{
        {Method: "GET", Path: "/", Code: 200},
    }...)
}
```

## Important Development Notes

1. **Redis Required**: Most tests and features require Redis running on localhost:6379
2. **Enterprise Features**: Code in `ee/` folder requires commercial license
3. **Configuration**: Can be set via file, environment variables (TYK_GW_*), or command line
4. **Hot Reload**: Many settings support hot reload without restart
5. **Logging**: Set `TYK_LOGLEVEL=debug` for detailed logs
6. **Test Framework**: Use the custom test framework in `test/` package for consistency

## Common Tasks

### Adding New Middleware

1. Create `gateway/mw_your_feature.go`
2. Implement `BaseMiddleware` interface
3. Add to middleware chain in `gateway/mw_chain.go`
4. Update API definition if needed in `apidef/`
5. Add tests following existing patterns

### Working with API Definitions

- Native format: JSON in `apidef/api_definitions.go`
- OpenAPI: Supported via `apidef/oas/` package
- GraphQL: Configuration in `graphql/` package
- Always validate changes with `ts.Gw.BuildAndLoadAPI()`

### Plugin Development

- Go plugins: Compile as `.so` with matching Go version
- Python/Lua: Place in `middleware/python` or `middleware/lua`
- gRPC: Implement dispatcher service interface
- Bundle format: ZIP with `manifest.json` and plugin files

## Debugging Tips

1. Use `gateway.log` for structured logging
2. Enable debug mode: `TYK_LOGLEVEL=debug`
3. Test with curl: `curl -H "x-api-key: key" http://localhost:8080/`
4. Check Redis: `redis-cli MONITOR` to see operations
5. Integration test logs: Set `TYK_LOGLEVEL=debug` before running tests