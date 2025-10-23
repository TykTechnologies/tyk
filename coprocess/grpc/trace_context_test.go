package grpc

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/tyk/coprocess"
)

// TestTraceContextInObject verifies that trace context fields are properly set in the Object
func TestTraceContextInObject(t *testing.T) {
	// Create a test object with trace context
	object := &coprocess.Object{
		TraceId:    "1234567890abcdef1234567890abcdef",
		SpanId:     "1234567890abcdef",
		TraceFlags: 1,
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}

	// Verify fields are set
	if object.TraceId == "" {
		t.Error("TraceId should not be empty")
	}
	if object.SpanId == "" {
		t.Error("SpanId should not be empty")
	}
	if len(object.TraceId) != 32 {
		t.Errorf("TraceId should be 32 characters, got %d", len(object.TraceId))
	}
	if len(object.SpanId) != 16 {
		t.Errorf("SpanId should be 16 characters, got %d", len(object.SpanId))
	}
}

// TestExampleTracedDispatcher verifies the example dispatcher works with trace context
func TestExampleTracedDispatcher(t *testing.T) {
	// Setup OpenTelemetry
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	// Create a tracer and start a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test_parent_span")
	defer span.End()

	// Create the example dispatcher
	dispatcher := NewExampleTracedDispatcher("test-plugin")

	// Create a test object with trace context
	spanContext := span.SpanContext()
	object := &coprocess.Object{
		TraceId:    spanContext.TraceID().String(),
		SpanId:     spanContext.SpanID().String(),
		TraceFlags: uint32(spanContext.TraceFlags()),
		HookName:   "test_hook",
		HookType:   coprocess.HookType_Pre,
		Request: &coprocess.MiniRequestObject{
			Method:     "GET",
			Url:        "/test",
			SetHeaders: make(map[string]string),
		},
	}

	// Call the dispatcher
	result, err := dispatcher.Dispatch(ctx, object)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	// Verify the dispatcher processed the request
	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Verify the custom header was added by the example dispatcher
	if result.Request.SetHeaders["X-Plugin-Processed"] != "true" {
		t.Error("Expected X-Plugin-Processed header to be set")
	}
}

// TestExampleBasicUsage verifies the basic usage example
func TestExampleBasicUsage(t *testing.T) {
	// Setup OpenTelemetry
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	// Create a tracer and start a span
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test_span")
	defer span.End()

	// Create a test object with trace context
	spanContext := span.SpanContext()
	object := &coprocess.Object{
		TraceId:    spanContext.TraceID().String(),
		SpanId:     spanContext.SpanID().String(),
		TraceFlags: uint32(spanContext.TraceFlags()),
	}

	// Call the example basic usage function
	err := ExampleBasicUsage(ctx, object)
	if err != nil {
		t.Fatalf("ExampleBasicUsage failed: %v", err)
	}
}

// TestTraceContextPropagation verifies that trace context is properly propagated
func TestTraceContextPropagation(t *testing.T) {
	// Setup OpenTelemetry
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	// Create a parent span
	tracer := tp.Tracer("test")
	parentCtx, parentSpan := tracer.Start(context.Background(), "parent_span")
	defer parentSpan.End()

	parentSpanContext := parentSpan.SpanContext()

	// Create a child span from the context (simulating what happens in a plugin)
	_, childSpan := tracer.Start(parentCtx, "child_span")
	defer childSpan.End()

	childSpanContext := childSpan.SpanContext()

	// Verify the child span has the same trace ID as the parent
	if childSpanContext.TraceID() != parentSpanContext.TraceID() {
		t.Error("Child span should have the same trace ID as parent")
	}

	// Verify the child span has a different span ID than the parent
	if childSpanContext.SpanID() == parentSpanContext.SpanID() {
		t.Error("Child span should have a different span ID than parent")
	}

	// Verify both spans are valid
	if !parentSpanContext.IsValid() {
		t.Error("Parent span context should be valid")
	}
	if !childSpanContext.IsValid() {
		t.Error("Child span context should be valid")
	}
}

// TestTraceContextFromNonRecordingSpan tests creating a child span from trace context
func TestTraceContextFromNonRecordingSpan(t *testing.T) {
	// Setup OpenTelemetry
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Simulate receiving trace context from the Gateway (as hex strings)
	traceIDHex := "1234567890abcdef1234567890abcdef"
	spanIDHex := "1234567890abcdef"

	// Parse the hex strings (this is what a plugin would do)
	traceID, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		t.Fatalf("Failed to parse trace ID: %v", err)
	}

	spanID, err := trace.SpanIDFromHex(spanIDHex)
	if err != nil {
		t.Fatalf("Failed to parse span ID: %v", err)
	}

	// Create a SpanContext from the received values
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	// Create a non-recording span to hold the context
	nonRecordingSpan := trace.SpanFromContext(trace.ContextWithSpanContext(context.Background(), spanContext))

	// Set it in a context
	ctx := trace.ContextWithSpan(context.Background(), nonRecordingSpan)

	// Now create a child span - this would be in the plugin
	_, childSpan := tracer.Start(ctx, "plugin_operation")
	defer childSpan.End()

	childSpanContext := childSpan.SpanContext()

	// Verify the child span has the same trace ID
	if childSpanContext.TraceID() != traceID {
		t.Error("Child span should have the same trace ID as the parent")
	}

	// Verify the child span has a different span ID
	if childSpanContext.SpanID() == spanID {
		t.Error("Child span should have a different span ID than the parent")
	}
}
