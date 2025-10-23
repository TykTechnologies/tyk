// Package grpc provides an example gRPC plugin implementation with OpenTelemetry tracing support.
// This file demonstrates how to implement a gRPC plugin that participates in distributed tracing.
package grpc

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/tyk/coprocess"
)

// ExampleTracedDispatcher demonstrates how to implement a gRPC plugin
// that participates in OpenTelemetry distributed tracing.
//
// This is an example implementation showing best practices for:
// 1. Extracting trace context from incoming requests
// 2. Creating child spans for plugin operations
// 3. Adding custom attributes to spans
// 4. Properly handling span lifecycle
type ExampleTracedDispatcher struct {
	coprocess.UnimplementedDispatcherServer
	tracer trace.Tracer
}

// NewExampleTracedDispatcher creates a new dispatcher with OpenTelemetry tracing enabled.
// The serviceName parameter is used to identify this plugin in traces.
func NewExampleTracedDispatcher(serviceName string) *ExampleTracedDispatcher {
	// Get a tracer from the global TracerProvider
	// In a real plugin, you would typically configure your own TracerProvider
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	
	return &ExampleTracedDispatcher{
		tracer: tracer,
	}
}

// Dispatch handles incoming requests and demonstrates how to create spans
// for plugin operations that appear as part of the parent trace.
func (d *ExampleTracedDispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	// Create a child span for this plugin's operation
	// This span will automatically be associated with the parent span
	// from the Gateway thanks to gRPC's automatic trace context propagation
	ctx, span := d.tracer.Start(ctx, "grpc.plugin.dispatch")
	defer span.End()

	// Add custom attributes to the span to provide additional context
	span.SetAttributes(
		attribute.String("plugin.hook_name", object.HookName),
		attribute.String("plugin.hook_type", object.HookType.String()),
		attribute.String("request.method", object.Request.Method),
		attribute.String("request.path", object.Request.Url),
	)

	// If the object contains trace context fields, you can log them or use them
	// Note: When using gRPC with OpenTelemetry interceptors, the trace context
	// is automatically propagated through gRPC metadata, so these fields are
	// informational and can be used for logging or debugging
	if object.TraceId != "" {
		span.SetAttributes(
			attribute.String("tyk.trace_id", object.TraceId),
			attribute.String("tyk.span_id", object.SpanId),
		)
	}

	// Perform your plugin logic here
	// For this example, we'll just add a custom header
	err := d.processRequest(ctx, object)
	if err != nil {
		// Record the error in the span
		span.RecordError(err)
		return nil, err
	}

	return object, nil
}

// processRequest demonstrates how to create nested spans for different
// operations within your plugin.
func (d *ExampleTracedDispatcher) processRequest(ctx context.Context, object *coprocess.Object) error {
	// Create a nested span for a specific operation
	ctx, span := d.tracer.Start(ctx, "grpc.plugin.process_request")
	defer span.End()

	// Example: Add a custom header
	if object.Request.SetHeaders == nil {
		object.Request.SetHeaders = make(map[string]string)
	}
	object.Request.SetHeaders["X-Plugin-Processed"] = "true"
	
	// Add an attribute showing what we did
	span.SetAttributes(
		attribute.Bool("header.added", true),
		attribute.String("header.name", "X-Plugin-Processed"),
	)

	// You can create additional spans for database queries, API calls, etc.
	// Each will appear as a child span in the trace
	if err := d.simulateExternalCall(ctx); err != nil {
		return err
	}

	return nil
}

// simulateExternalCall demonstrates creating a span for an external operation
// like a database query or API call.
func (d *ExampleTracedDispatcher) simulateExternalCall(ctx context.Context) error {
	ctx, span := d.tracer.Start(ctx, "external.api.call",
		trace.WithAttributes(
			attribute.String("api.endpoint", "https://example.com/api"),
		),
	)
	defer span.End()

	// Simulate some work
	// In a real plugin, you would make your actual API call here
	// and the span would show the duration of that call in the trace

	return nil
}

// DispatchEvent handles event dispatches. This example doesn't trace events,
// but you could apply similar patterns if needed.
func (d *ExampleTracedDispatcher) DispatchEvent(ctx context.Context, event *coprocess.Event) (*coprocess.EventReply, error) {
	// You can add tracing for events too if needed
	ctx, span := d.tracer.Start(ctx, "grpc.plugin.dispatch_event")
	defer span.End()

	span.SetAttributes(
		attribute.Int("event.payload_length", len(event.Payload)),
	)

	return &coprocess.EventReply{}, nil
}

// Example of how to use this in a main function of your gRPC plugin:
//
// func main() {
//     // Initialize OpenTelemetry (you would need to configure exporter, etc.)
//     // This is just a basic example - in production you'd want proper configuration
//     
//     // Create a gRPC server
//     lis, err := net.Listen("tcp", ":50051")
//     if err != nil {
//         log.Fatalf("failed to listen: %v", err)
//     }
//
//     // Create gRPC server with OpenTelemetry interceptors
//     grpcServer := grpc.NewServer(
//         grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
//         grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
//     )
//
//     // Register our traced dispatcher
//     dispatcher := NewExampleTracedDispatcher("my-grpc-plugin")
//     coprocess.RegisterDispatcherServer(grpcServer, dispatcher)
//
//     // Start serving
//     log.Printf("gRPC server listening on :50051")
//     if err := grpcServer.Serve(lis); err != nil {
//         log.Fatalf("failed to serve: %v", err)
//     }
// }

// ExampleBasicUsage demonstrates basic usage without detailed tracing.
// This is useful if you just want to access the trace context for logging
// but don't need to create your own spans.
func ExampleBasicUsage(ctx context.Context, object *coprocess.Object) error {
	// Extract the span from context for logging purposes
	span := trace.SpanFromContext(ctx)
	spanContext := span.SpanContext()
	
	if spanContext.HasTraceID() {
		// You can log the trace ID for correlation
		fmt.Printf("Processing request with trace ID: %s\n", spanContext.TraceID().String())
		
		// Or add it to your custom logging system
		// logger.WithField("trace.id", spanContext.TraceID().String()).Info("Processing request")
	}

	// You can also access the trace context from the object fields
	if object.TraceId != "" {
		fmt.Printf("Object contains trace ID: %s\n", object.TraceId)
	}

	return nil
}
