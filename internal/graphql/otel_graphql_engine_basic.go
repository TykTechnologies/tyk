package graphql

import (
	"context"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"
	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
	"github.com/TykTechnologies/tyk/internal/otel"
)

// OtelGraphqlEngineV2Basic defines a struct that can be used for basic tracing with OTel.
// All execution stages are squashed into one span: GraphqlEngine. The upstream request still
// has its span and GraphqlEngine is its parent span.
type OtelGraphqlEngineV2Basic struct {
	otelGraphqlEngineV2Common
}

func (o *OtelGraphqlEngineV2Basic) Normalize(operation *graphql.Request) error {
	opType, err := operation.OperationType()
	if err != nil {
		return err
	}
	err = o.engine.Normalize(operation)
	if err != nil {
		_, span := o.tracerProvider.Tracer().Start(o.traceContext, "GraphqlMiddleware Validation")
		defer span.End()

		span.SetAttributes(
			semconv.GraphQLOperationName(operation.OperationName),
			semconv.GraphQLOperationType(PrintOperationType(ast.OperationType(opType))),
			semconv.GraphQLDocument(operation.Query),
		)
		return err
	}
	return nil
}

func (o *OtelGraphqlEngineV2Basic) ValidateForSchema(operation *graphql.Request) error {
	return o.engine.ValidateForSchema(operation)
}

func (o *OtelGraphqlEngineV2Basic) Setup(ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2) {
	o.engine.Setup(ctx, postProcessor, resolveContext, operation, options...)
}

func (o *OtelGraphqlEngineV2Basic) Plan(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error) {
	return o.engine.Plan(postProcessor, operation, report)
}

func (o *OtelGraphqlEngineV2Basic) Resolve(resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error {
	// Replacing the internal context is required to make a hierarchy between the execution and the upstream spans.
	resolveContext = resolveContext.WithContext(o.traceContext)
	return o.engine.Resolve(resolveContext, planResult, writer)
}

func (o *OtelGraphqlEngineV2Basic) Teardown() {}

func (o *OtelGraphqlEngineV2Basic) InputValidation(operation *graphql.Request) error {
	return o.engine.InputValidation(operation)
}

func (o *OtelGraphqlEngineV2Basic) Execute(inCtx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error {
	ctx, span := o.tracerProvider.Tracer().Start(inCtx, "GraphqlEngine")
	defer span.End()

	o.SetContext(ctx)

	operationType, err := operation.OperationType()
	if err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed to get operation type")
		return err
	}

	span.SetAttributes(
		semconv.GraphQLOperationName(operation.OperationName),
		semconv.GraphQLOperationType(PrintOperationType(ast.OperationType(operationType))),
		semconv.GraphQLDocument(operation.Query),
	)

	if err := o.executor.Execute(inCtx, operation, writer, options...); err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed to execute")
		return err
	}
	return nil
}

func NewOtelGraphqlEngineV2Basic(tracerProvider otel.TracerProvider, engine ExecutionEngineI) (*OtelGraphqlEngineV2Basic, error) {
	otelEngine := &OtelGraphqlEngineV2Basic{
		otelGraphqlEngineV2Common{
			tracerProvider: tracerProvider,
			engine:         engine,
		},
	}
	executor, err := graphql.NewCustomExecutionEngineV2Executor(otelEngine)
	if err != nil {
		return nil, err
	}

	otelEngine.executor = executor
	return otelEngine, nil
}

var _ TykOtelExecutorI = (*OtelGraphqlEngineV2Basic)(nil)
