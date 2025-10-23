# OpenTelemetry Tracing in gRPC Plugins

This guide explains how to implement OpenTelemetry distributed tracing in your gRPC plugins for Tyk Gateway.

## Overview

When OpenTelemetry is enabled in Tyk Gateway, trace context is automatically propagated to gRPC plugins through gRPC metadata. This allows your plugin to create spans that appear as part of the same trace that tracks the request through the Gateway.

## Benefits

- **End-to-end visibility**: See the complete journey of an API request, including what happens inside your plugins
- **Performance monitoring**: Identify bottlenecks in plugin processing
- **Debugging**: Trace issues across the Gateway and plugin boundaries
- **Custom metrics**: Add your own attributes and spans for business-specific operations

## How It Works

1. **Gateway receives request** with trace context (or creates a new trace)
2. **Gateway passes request to plugin** via gRPC with trace context in metadata
3. **Plugin creates child spans** for its operations
4. **Plugin returns response** to Gateway
5. **Complete trace** is visible in your observability platform (Jaeger, Datadog, etc.)

## Implementation

### Prerequisites

```bash
go get go.opentelemetry.io/otel
go get go.opentelemetry.io/otel/trace
go get go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc
```

### Basic Setup

#### 1. Initialize OpenTelemetry in Your Plugin

```go
import (
    "context"
    "log"
    
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/sdk/trace"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func initTracing() (*sdktrace.TracerProvider, error) {
    // Create an OTLP exporter
    exporter, err := otlptracegrpc.New(context.Background(),
        otlptracegrpc.WithEndpoint("localhost:4317"),
        otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, err
    }

    // Create a tracer provider
    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter),
        sdktrace.WithSampler(sdktrace.AlwaysSample()),
    )
    
    // Set as global tracer provider
    otel.SetTracerProvider(tp)
    
    return tp, nil
}
```

#### 2. Create gRPC Server with OpenTelemetry Interceptors

```go
import (
    "google.golang.org/grpc"
    "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
)

func main() {
    // Initialize tracing
    tp, err := initTracing()
    if err != nil {
        log.Fatalf("failed to initialize tracing: %v", err)
    }
    defer tp.Shutdown(context.Background())

    // Create gRPC server with OpenTelemetry interceptors
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
        grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
    )

    // Register your dispatcher
    coprocess.RegisterDispatcherServer(grpcServer, &MyDispatcher{})
    
    // Start serving...
}
```

#### 3. Implement Your Dispatcher with Tracing

```go
import (
    "context"
    
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
    
    "github.com/TykTechnologies/tyk/coprocess"
)

type MyDispatcher struct {
    coprocess.UnimplementedDispatcherServer
    tracer trace.Tracer
}

func (d *MyDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    // Create a span for your plugin operation
    ctx, span := d.tracer.Start(ctx, "my_plugin.process_request")
    defer span.End()

    // Add attributes to the span
    span.SetAttributes(
        attribute.String("request.method", object.Request.Method),
        attribute.String("request.path", object.Request.Url),
        attribute.String("hook.name", object.HookName),
    )

    // Do your plugin logic
    // Any operations here will be measured by the span duration
    
    return object, nil
}
```

### Advanced Usage

#### Creating Nested Spans

```go
func (d *MyDispatcher) processRequest(ctx context.Context, object *coprocess.Object) error {
    // Create a child span for database operation
    ctx, dbSpan := d.tracer.Start(ctx, "database.query")
    dbSpan.SetAttributes(
        attribute.String("db.system", "postgresql"),
        attribute.String("db.statement", "SELECT * FROM users WHERE id = ?"),
    )
    
    // Execute database query
    result, err := d.db.Query(ctx, "SELECT * FROM users WHERE id = ?", userID)
    dbSpan.End()
    
    if err != nil {
        dbSpan.RecordError(err)
        return err
    }

    // Create another span for external API call
    ctx, apiSpan := d.tracer.Start(ctx, "external.api.call")
    apiSpan.SetAttributes(
        attribute.String("api.endpoint", "https://api.example.com/users"),
    )
    
    // Make API call
    resp, err := d.httpClient.Get(ctx, "https://api.example.com/users")
    apiSpan.End()
    
    if err != nil {
        apiSpan.RecordError(err)
        return err
    }

    return nil
}
```

#### Recording Errors

```go
func (d *MyDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    ctx, span := d.tracer.Start(ctx, "my_plugin.process")
    defer span.End()

    err := d.processRequest(ctx, object)
    if err != nil {
        // Record the error in the span
        span.RecordError(err)
        span.SetAttributes(
            attribute.String("error.type", "validation_error"),
            attribute.String("error.message", err.Error()),
        )
        return nil, err
    }

    return object, nil
}
```

#### Adding Custom Events

```go
func (d *MyDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    ctx, span := d.tracer.Start(ctx, "my_plugin.process")
    defer span.End()

    // Add an event to the span
    span.AddEvent("validation.started")
    
    if err := d.validateRequest(object); err != nil {
        span.AddEvent("validation.failed", trace.WithAttributes(
            attribute.String("reason", err.Error()),
        ))
        return nil, err
    }
    
    span.AddEvent("validation.succeeded")

    return object, nil
}
```

## Accessing Trace Context

The trace context is available in two ways:

### 1. From the Context (Recommended for gRPC)

```go
func (d *MyDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    // Extract span from context
    span := trace.SpanFromContext(ctx)
    spanContext := span.SpanContext()
    
    if spanContext.HasTraceID() {
        traceID := spanContext.TraceID().String()
        spanID := spanContext.SpanID().String()
        
        // Use for logging
        log.Printf("Processing request with trace ID: %s, span ID: %s", traceID, spanID)
    }
    
    return object, nil
}
```

### 2. From the Object Fields

```go
func (d *MyDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    // The object contains trace context fields for informational purposes
    if object.TraceId != "" {
        log.Printf("Trace ID from object: %s", object.TraceId)
        log.Printf("Span ID from object: %s", object.SpanId)
        log.Printf("Trace flags: %d", object.TraceFlags)
    }
    
    return object, nil
}
```

**Note**: When using gRPC with OpenTelemetry interceptors, the trace context is automatically propagated through gRPC metadata. The object fields are provided for informational purposes and for use in non-gRPC plugins.

## Best Practices

### 1. Name Your Spans Clearly

Use descriptive names that indicate what operation is being performed:

```go
// Good
ctx, span := tracer.Start(ctx, "user.authentication")
ctx, span := tracer.Start(ctx, "cache.lookup")
ctx, span := tracer.Start(ctx, "database.query.users")

// Bad
ctx, span := tracer.Start(ctx, "process")
ctx, span := tracer.Start(ctx, "step1")
```

### 2. Add Meaningful Attributes

```go
span.SetAttributes(
    attribute.String("user.id", userID),
    attribute.String("api.version", "v1"),
    attribute.Int("cache.ttl", 3600),
    attribute.Bool("cache.hit", true),
)
```

### 3. Always Close Spans

Use `defer` to ensure spans are closed:

```go
func process(ctx context.Context) error {
    ctx, span := tracer.Start(ctx, "process")
    defer span.End() // Always called, even if function returns early
    
    // ... your code ...
}
```

### 4. Record Errors Properly

```go
if err != nil {
    span.RecordError(err)
    span.SetAttributes(attribute.String("error.type", "database_error"))
    return err
}
```

### 5. Don't Create Too Many Spans

Create spans for meaningful operations (database queries, API calls, complex computations), but avoid creating spans for trivial operations.

## Testing

### Testing with Trace Context

You can test your plugin with trace context:

```go
import (
    "context"
    "testing"
    
    "go.opentelemetry.io/otel"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    "go.opentelemetry.io/otel/trace"
)

func TestDispatchWithTracing(t *testing.T) {
    // Create a test tracer provider
    tp := sdktrace.NewTracerProvider()
    otel.SetTracerProvider(tp)
    
    // Create a test span
    tracer := tp.Tracer("test")
    ctx, span := tracer.Start(context.Background(), "test_span")
    defer span.End()
    
    // Create your dispatcher
    dispatcher := &MyDispatcher{tracer: tracer}
    
    // Create test object
    object := &coprocess.Object{
        Request: &coprocess.MiniRequestObject{
            Method: "GET",
            Url:    "/test",
        },
    }
    
    // Call Dispatch with traced context
    result, err := dispatcher.Dispatch(ctx, object)
    if err != nil {
        t.Fatalf("Dispatch failed: %v", err)
    }
    
    // Verify result
    // ...
}
```

## Common Patterns

### Pattern 1: Authentication Plugin

```go
func (d *AuthPlugin) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    ctx, span := d.tracer.Start(ctx, "auth.validate_token")
    defer span.End()

    // Extract token
    token := object.Request.Headers["Authorization"]
    span.SetAttributes(attribute.Bool("token.present", token != ""))

    // Validate token (creates child span)
    ctx, validateSpan := d.tracer.Start(ctx, "auth.token.validate")
    user, err := d.validateToken(ctx, token)
    validateSpan.End()
    
    if err != nil {
        span.RecordError(err)
        return nil, err
    }

    // Add user info to span
    span.SetAttributes(
        attribute.String("user.id", user.ID),
        attribute.String("user.role", user.Role),
    )

    return object, nil
}
```

### Pattern 2: Rate Limiting Plugin

```go
func (d *RateLimitPlugin) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
    ctx, span := d.tracer.Start(ctx, "ratelimit.check")
    defer span.End()

    key := object.Request.Headers["X-API-Key"]
    
    // Check rate limit
    ctx, checkSpan := d.tracer.Start(ctx, "ratelimit.redis.get")
    count, err := d.redis.Get(ctx, key)
    checkSpan.SetAttributes(
        attribute.String("redis.key", key),
        attribute.Int("current.count", count),
    )
    checkSpan.End()
    
    if err != nil {
        span.RecordError(err)
        return nil, err
    }

    if count > d.limit {
        span.SetAttributes(attribute.Bool("rate_limit.exceeded", true))
        return nil, fmt.Errorf("rate limit exceeded")
    }

    return object, nil
}
```

## Troubleshooting

### No Traces Appearing

1. Verify OpenTelemetry is enabled in Tyk Gateway configuration
2. Check that gRPC interceptors are configured on both client (Gateway) and server (plugin)
3. Verify your tracer provider is properly initialized
4. Check exporter configuration and connectivity

### Disconnected Traces

If your plugin traces appear separately from Gateway traces:
- Ensure `otelgrpc.UnaryServerInterceptor()` is added to your gRPC server
- Verify the Gateway has gRPC client interceptors configured
- Check that you're using the `ctx` parameter passed to `Dispatch()`

### Missing Spans

- Verify you're calling `defer span.End()`
- Check that your tracer provider is flushing/exporting
- Ensure sampling is configured appropriately

## Example Projects

See `example_tracer.go` in this directory for a complete working example.

## References

- [OpenTelemetry Go Documentation](https://opentelemetry.io/docs/instrumentation/go/)
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/otel/)
- [gRPC OpenTelemetry Instrumentation](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc)
