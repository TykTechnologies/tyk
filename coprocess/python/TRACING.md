# OpenTelemetry Tracing in Python Plugins

This guide explains how to implement OpenTelemetry distributed tracing in your Python plugins for Tyk Gateway.

## Overview

When OpenTelemetry is enabled in Tyk Gateway, trace context is automatically propagated to Python plugins through the `Object` protobuf message. The trace context is available in the `trace_id`, `span_id`, and `trace_flags` fields.

## Benefits

- **End-to-end visibility**: See the complete journey of an API request, including what happens inside your plugins
- **Performance monitoring**: Identify bottlenecks in plugin processing
- **Debugging**: Trace issues across the Gateway and plugin boundaries
- **Correlation**: Correlate plugin logs with distributed traces using trace IDs

## How It Works

1. **Gateway receives request** with trace context (or creates a new trace)
2. **Gateway passes request to plugin** with trace context in the Object fields
3. **Plugin can access trace context** for logging or creating child spans
4. **Plugin returns response** to Gateway
5. **Complete trace** is visible in your observability platform

## Implementation

### Prerequisites

```bash
pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp
```

### Basic Setup

#### 1. Initialize OpenTelemetry in Your Plugin

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# Initialize tracer provider
trace.set_tracer_provider(TracerProvider())
tracer_provider = trace.get_tracer_provider()

# Configure OTLP exporter
otlp_exporter = OTLPSpanExporter(
    endpoint="localhost:4317",
    insecure=True
)

# Add span processor
tracer_provider.add_span_processor(
    BatchSpanProcessor(otlp_exporter)
)

# Get a tracer
tracer = trace.get_tracer("my-python-plugin")
```

#### 2. Access Trace Context in Your Middleware

```python
from opentelemetry import trace
from opentelemetry.trace import SpanContext, TraceFlags

def MyMiddleware(request, session, spec):
    # Access trace context from the request object
    trace_id_hex = request.trace_id
    span_id_hex = request.span_id
    trace_flags = request.trace_flags
    
    # If trace context is present, create a child span
    if trace_id_hex and span_id_hex:
        # Convert hex strings to integers
        trace_id = int(trace_id_hex, 16)
        span_id = int(span_id_hex, 16)
        
        # Create a SpanContext from the propagated values
        span_context = SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            is_remote=True,
            trace_flags=TraceFlags(trace_flags)
        )
        
        # Create a context from the span context
        ctx = trace.set_span_in_context(
            trace.NonRecordingSpan(span_context)
        )
        
        # Start a new child span
        with tracer.start_as_current_span("python.plugin.process", context=ctx) as span:
            # Add attributes
            span.set_attribute("plugin.hook", "pre")
            span.set_attribute("request.method", request.method)
            span.set_attribute("request.path", request.url)
            
            # Do your plugin logic
            process_request(request)
    else:
        # No trace context, just process normally
        process_request(request)
    
    return request, session
```

### Example Plugin with Tracing

```python
from opentelemetry import trace
from opentelemetry.trace import SpanContext, TraceFlags, Status, StatusCode
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# Initialize tracing once at module level
trace.set_tracer_provider(TracerProvider())
tracer_provider = trace.get_tracer_provider()

otlp_exporter = OTLPSpanExporter(
    endpoint="localhost:4317",
    insecure=True
)

tracer_provider.add_span_processor(
    BatchSpanProcessor(otlp_exporter)
)

tracer = trace.get_tracer("tyk-python-plugin")


def create_span_context(trace_id_hex, span_id_hex, trace_flags):
    """Helper function to create a SpanContext from the propagated trace context."""
    if not trace_id_hex or not span_id_hex:
        return None
    
    try:
        trace_id = int(trace_id_hex, 16)
        span_id = int(span_id_hex, 16)
        
        return SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            is_remote=True,
            trace_flags=TraceFlags(trace_flags if trace_flags else 0)
        )
    except ValueError:
        return None


def MyPreMiddleware(request, session, spec):
    """Pre-middleware with OpenTelemetry tracing support."""
    
    # Extract trace context
    span_context = create_span_context(
        request.trace_id,
        request.span_id,
        request.trace_flags
    )
    
    if span_context:
        # Create a context with the parent span
        ctx = trace.set_span_in_context(
            trace.NonRecordingSpan(span_context)
        )
        
        # Start a child span
        with tracer.start_as_current_span(
            "python.plugin.pre_middleware",
            context=ctx
        ) as span:
            span.set_attribute("request.method", request.method)
            span.set_attribute("request.path", request.url)
            span.set_attribute("plugin.type", "pre")
            
            try:
                # Perform authentication check (example)
                with tracer.start_as_current_span("auth.validate_token"):
                    api_key = request.headers.get("X-API-Key", "")
                    if not api_key:
                        span.set_status(Status(StatusCode.ERROR, "Missing API key"))
                        request.return_overrides.response_code = 401
                        request.return_overrides.response_error = "Missing API key"
                        return request, session
                
                # Add custom header
                with tracer.start_as_current_span("request.modify_headers"):
                    request.set_headers["X-Plugin-Processed"] = "true"
                    
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
    else:
        # No trace context, process without tracing
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            request.return_overrides.response_code = 401
            request.return_overrides.response_error = "Missing API key"
            return request, session
        
        request.set_headers["X-Plugin-Processed"] = "true"
    
    return request, session


def MyPostMiddleware(request, session, spec):
    """Post-middleware with OpenTelemetry tracing support."""
    
    span_context = create_span_context(
        request.trace_id,
        request.span_id,
        request.trace_flags
    )
    
    if span_context:
        ctx = trace.set_span_in_context(
            trace.NonRecordingSpan(span_context)
        )
        
        with tracer.start_as_current_span(
            "python.plugin.post_middleware",
            context=ctx
        ) as span:
            span.set_attribute("session.quota_max", session.quota_max)
            span.set_attribute("session.quota_remaining", session.quota_remaining)
            
            # Add custom metadata
            with tracer.start_as_current_span("session.update_metadata"):
                session.metadata["processed_at"] = str(time.time())
    else:
        # No trace context, process without tracing
        session.metadata["processed_at"] = str(time.time())
    
    return request, session


def MyResponseMiddleware(request, session, spec):
    """Response middleware with OpenTelemetry tracing support."""
    
    span_context = create_span_context(
        request.trace_id,
        request.span_id,
        request.trace_flags
    )
    
    if span_context:
        ctx = trace.set_span_in_context(
            trace.NonRecordingSpan(span_context)
        )
        
        with tracer.start_as_current_span(
            "python.plugin.response_middleware",
            context=ctx
        ) as span:
            # Access response data
            status_code = request.response.status_code
            span.set_attribute("response.status_code", status_code)
            
            # Modify response if needed
            if status_code >= 500:
                span.set_status(Status(StatusCode.ERROR, "Server error"))
                with tracer.start_as_current_span("response.add_error_header"):
                    request.response.headers["X-Error-Processed"] = "true"
    else:
        # No trace context, process without tracing
        if request.response.status_code >= 500:
            request.response.headers["X-Error-Processed"] = "true"
    
    return request, session
```

## Logging with Trace Context

Even if you don't create spans, you can use the trace context for log correlation:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - trace_id=%(trace_id)s - %(message)s'
)
logger = logging.getLogger(__name__)


def MyMiddleware(request, session, spec):
    # Extract trace ID for logging
    trace_id = request.trace_id if request.trace_id else "no-trace"
    
    # Log with trace context
    logger.info(
        "Processing request",
        extra={'trace_id': trace_id}
    )
    
    # Your plugin logic
    try:
        process_request(request)
        logger.info(
            "Request processed successfully",
            extra={'trace_id': trace_id}
        )
    except Exception as e:
        logger.error(
            f"Error processing request: {e}",
            extra={'trace_id': trace_id}
        )
        raise
    
    return request, session
```

## Best Practices

### 1. Check for Trace Context Availability

Always check if trace context is present before trying to use it:

```python
if request.trace_id and request.span_id:
    # Create traced span
    pass
else:
    # Process without tracing
    pass
```

### 2. Handle Errors Properly

Record exceptions in spans:

```python
try:
    process_request(request)
except Exception as e:
    span.record_exception(e)
    span.set_status(Status(StatusCode.ERROR, str(e)))
    raise
```

### 3. Add Meaningful Attributes

```python
span.set_attribute("user.id", user_id)
span.set_attribute("api.version", "v1")
span.set_attribute("cache.hit", cache_hit)
```

### 4. Use Nested Spans for Operations

```python
with tracer.start_as_current_span("parent_operation"):
    # Nested operation
    with tracer.start_as_current_span("database.query"):
        result = query_database()
    
    # Another nested operation
    with tracer.start_as_current_span("cache.update"):
        update_cache(result)
```

## Testing

You can test your plugin with mock trace context:

```python
def test_middleware_with_trace_context():
    # Create a mock request with trace context
    request = MockRequest()
    request.trace_id = "1234567890abcdef1234567890abcdef"
    request.span_id = "1234567890abcdef"
    request.trace_flags = 1
    
    session = MockSession()
    spec = {}
    
    # Call your middleware
    result_request, result_session = MyMiddleware(request, session, spec)
    
    # Verify behavior
    assert result_request.set_headers["X-Plugin-Processed"] == "true"
```

## Troubleshooting

### Trace Context Not Available

If `request.trace_id` is empty:
1. Verify OpenTelemetry is enabled in Tyk Gateway configuration
2. Check that the Gateway is receiving requests with trace context
3. Ensure you're accessing the trace context in the right middleware hook

### Disconnected Traces

If your plugin traces appear separately from Gateway traces:
1. Verify you're creating the SpanContext correctly from the propagated values
2. Check that the trace_id and span_id are being parsed as hexadecimal strings
3. Ensure `is_remote=True` when creating the SpanContext

## Example Complete Plugin

See the example above for a complete working plugin with pre, post, and response hooks all supporting OpenTelemetry tracing.

## References

- [OpenTelemetry Python Documentation](https://opentelemetry.io/docs/instrumentation/python/)
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/otel/)
- [Python OpenTelemetry API](https://opentelemetry-python.readthedocs.io/)
