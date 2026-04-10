package graphql

import (
	"context"
	"sync"

	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/lexer/literal"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"
	"github.com/TykTechnologies/tyk/internal/otel"
)

type ExecutionEngineI interface {
	graphql.CustomExecutionEngineV2
	graphql.ExecutionEngineV2Executor
}

// TykOtelExecutorI is an interface that inherits ExecutionEngineI and defines Tyk/UDG
// specific methods.
type TykOtelExecutorI interface {
	ExecutionEngineI

	// SetContext sets the current OTel tracer context.
	SetContext(ctx context.Context)
}

// otelGraphqlEngineV2Common is a struct that implements the common/default methods of TykOtelExecutorI interface.
type otelGraphqlEngineV2Common struct {
	mutex          sync.Mutex
	traceContext   context.Context
	tracerProvider otel.TracerProvider

	engine   ExecutionEngineI
	executor graphql.ExecutionEngineV2Executor
}

func (o *otelGraphqlEngineV2Common) SetContext(ctx context.Context) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	o.traceContext = ctx
}

// OtelGraphqlEngineV2Detailed defines an execution engine that can be used for detailed tracing with OTel.
type OtelGraphqlEngineV2Detailed struct {
	otelGraphqlEngineV2Common
	schema *graphql.Schema
}

func (o *OtelGraphqlEngineV2Detailed) Normalize(operation *graphql.Request) error {
	if operation.IsNormalized() {
		return nil
	}
	var operationName = "NormalizeRequest"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	err := o.engine.Normalize(operation)
	if err != nil {
		operationType, _ := operation.OperationType()
		span.SetAttributes(
			semconv.GraphQLOperationName(operation.OperationName),
			semconv.GraphQLOperationType(PrintOperationType(ast.OperationType(operationType))),
			semconv.GraphQLDocument(operation.Query),
		)
		span.SetStatus(otel.SPAN_STATUS_ERROR, "request normalization failed")
		return err
	}
	return nil
}

func (o *OtelGraphqlEngineV2Detailed) ValidateForSchema(operation *graphql.Request) error {
	if operation.IsValidated(o.schema) {
		return nil
	}
	var operationName = "ValidateRequest"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()

	operationType, err := operation.OperationType()
	if err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "request validation failed")
		return err
	}

	span.SetAttributes(
		semconv.GraphQLOperationName(operation.OperationName),
		semconv.GraphQLOperationType(PrintOperationType(ast.OperationType(operationType))),
		semconv.GraphQLDocument(operation.Query),
	)

	err = o.engine.ValidateForSchema(operation)
	if err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "request validation failed")
		return err
	}
	return nil
}

func (o *OtelGraphqlEngineV2Detailed) Setup(ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2) {
	var operationName = "SetupResolver"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	o.engine.Setup(ctx, postProcessor, resolveContext, operation, options...)
}

func (o *OtelGraphqlEngineV2Detailed) Plan(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error) {
	var operationName = "GeneratePlan"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	p, err := o.engine.Plan(postProcessor, operation, report)
	if err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed to generate plan")
		return nil, err
	}
	return p, nil
}

func (o *OtelGraphqlEngineV2Detailed) Resolve(resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error {
	var operationName = "ResolvePlan"
	ctx, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	resolveContext = resolveContext.WithContext(ctx)
	if err := o.engine.Resolve(resolveContext, planResult, writer); err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed to resolve")
		return err
	}
	return nil
}

func (o *OtelGraphqlEngineV2Detailed) Teardown() {
}

func (o *OtelGraphqlEngineV2Detailed) InputValidation(operation *graphql.Request) error {
	var operationName = "InputValidation"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	if err := o.engine.InputValidation(operation); err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed input validation")
		return err
	}
	return nil
}

func (o *OtelGraphqlEngineV2Detailed) Execute(inCtx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error {
	ctx, span := o.tracerProvider.Tracer().Start(inCtx, "GraphqlEngine")
	defer span.End()
	o.SetContext(ctx)
	if err := o.executor.Execute(inCtx, operation, writer, options...); err != nil {
		span.SetStatus(otel.SPAN_STATUS_ERROR, "failed to execute")
		return err
	}
	return nil
}

/*
NewOtelGraphqlEngineV2Detailed creates a new instance of OtelGraphqlEngineV2Detailed.
It takes a tracer provider, an execution engine, and a GraphQL schema as parameters.
The function returns a pointer to OtelGraphqlEngineV2Detailed and an error if any.
*/
func NewOtelGraphqlEngineV2Detailed(tracerProvider otel.TracerProvider, engine ExecutionEngineI, schema *graphql.Schema) (*OtelGraphqlEngineV2Detailed, error) {
	otelEngine := &OtelGraphqlEngineV2Detailed{
		otelGraphqlEngineV2Common: otelGraphqlEngineV2Common{
			tracerProvider: tracerProvider,
			engine:         engine,
		},
		schema: schema,
	}
	executor, err := graphql.NewCustomExecutionEngineV2Executor(otelEngine)
	if err != nil {
		return nil, err
	}

	otelEngine.executor = executor
	return otelEngine, nil
}

func PrintOperationType(operationType ast.OperationType) string {
	switch operationType {
	case ast.OperationTypeQuery:
		return string(literal.QUERY)
	case ast.OperationTypeMutation:
		return string(literal.MUTATION)
	case ast.OperationTypeSubscription:
		return string(literal.SUBSCRIPTION)
	case ast.OperationTypeUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

var _ TykOtelExecutorI = (*OtelGraphqlEngineV2Detailed)(nil)
