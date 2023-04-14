package gateway

import (
	"context"
	"github.com/TykTechnologies/tyk/trace"
	"go.opentelemetry.io/otel/attribute"
	"sync"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	otelTrace "go.opentelemetry.io/otel/trace"
)

// ExecutionEngineWithOTel is a wrapper round the default implementation of graphql.ObservableExecutionEngine
// and graphql.ObservableExecutionStages interfaces. It adds OpenTelemetry spans to the execution and keeps the latest span context.
type ExecutionEngineWithOTel struct {
	mu        sync.Mutex
	ctx       context.Context
	tracerCtx context.Context
	rootSpan  otelTrace.Span
	tracer    trace.Tracer
	stages    graphql.ObservableExecutionStages
}

func (e *ExecutionEngineWithOTel) Setup(ctx context.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2) {
	e.stages.Setup(ctx, operation, options...)
}

func (e *ExecutionEngineWithOTel) Teardown() {
	e.stages.Teardown()
}

func (e *ExecutionEngineWithOTel) Normalize(operation *graphql.Request) error {
	ctx, span := e.tracer.Start(e.tracerCtx, "graphql.normalization")
	defer span.End()
	e.setCurrentContext(ctx)

	return e.stages.Normalize(operation)
}

func (e *ExecutionEngineWithOTel) ValidateForSchema(operation *graphql.Request) error {
	ctx, span := e.tracer.Start(e.tracerCtx, "graphql.validate-query-for-schema")
	defer span.End()
	e.setCurrentContext(ctx)

	// We can add any attributes to the spans. Here, we are adding the GQL query and operation name.
	// We can also add errors to the spans.
	var attr []attribute.KeyValue
	attr = append(attr, attribute.String("operation_name", operation.OperationName))
	attr = append(attr, attribute.String("query", operation.Query))
	span.SetAttributes(attr...)
	return e.stages.ValidateForSchema(operation)
}

func (e *ExecutionEngineWithOTel) Plan(operation *graphql.Request, report *operationreport.Report) (plan.Plan, error) {
	ctx, span := e.tracer.Start(e.tracerCtx, "graphql.planner")
	defer span.End()
	e.setCurrentContext(ctx)

	return e.stages.Plan(operation, report)
}

func (e *ExecutionEngineWithOTel) Resolve(plan plan.Plan, writer resolve.FlushWriter) error {
	ctx, span := e.tracer.Start(e.tracerCtx, "graphql.resolver")
	defer span.End()
	e.setCurrentContext(ctx)

	return e.stages.Resolve(plan, writer)
}

func NewExecutionEngineWithOTel(ctx context.Context, executionEngineV2 graphql.ObservableExecutionStages) graphql.ObservableExecutionEngine {
	return &ExecutionEngineWithOTel{
		ctx:    ctx,
		stages: executionEngineV2,
	}
}

func (e *ExecutionEngineWithOTel) Context() context.Context {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.tracerCtx
}

func (e *ExecutionEngineWithOTel) setCurrentContext(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tracerCtx = ctx
}

func (e *ExecutionEngineWithOTel) Execute(ctx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error {
	e.tracer = trace.Get("tyk-gateway")
	e.tracerCtx, e.rootSpan = e.tracer.Start(ctx, "graphql.execute")
	defer e.rootSpan.End()

	engine := graphql.NewObservableExecutionEngineV2(e)
	return engine.Execute(ctx, operation, writer, options...)
}

var (
	_ graphql.ObservableExecutionEngine = (*ExecutionEngineWithOTel)(nil)
	_ graphql.ObservableExecutionStages = (*ExecutionEngineWithOTel)(nil)
)
