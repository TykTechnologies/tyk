package gateway

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"
	"github.com/TykTechnologies/tyk/internal/otel"
)

type OtelGraphqlEngineV2 struct {
	mutex          sync.Mutex
	logger         *logrus.Entry
	spec           *APISpec
	traceContext   context.Context
	tracerProvider otel.TracerProvider

	engine       *graphql.ExecutionEngineV2
	rootExecutor graphql.ExecutionEngineV2Executor
}

func (o *OtelGraphqlEngineV2) setContext(ctx context.Context) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.traceContext = ctx
}

func (o *OtelGraphqlEngineV2) setRootExecutor(executor graphql.ExecutionEngineV2Executor) {
	o.rootExecutor = executor
}

func (o *OtelGraphqlEngineV2) Normalize(operation *graphql.Request) error {
	var operationName = "NormalizeRequest"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	return o.engine.Normalize(operation)
}

func (o *OtelGraphqlEngineV2) ValidateForSchema(operation *graphql.Request) error {
	var operationName = "ValidateRequest"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	return o.engine.ValidateForSchema(operation)
}

func (o *OtelGraphqlEngineV2) Setup(ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2) {
	var operationName = "SetupResolver"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	o.engine.Setup(ctx, postProcessor, resolveContext, operation, options...)
}

func (o *OtelGraphqlEngineV2) Plan(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error) {
	var operationName = "GeneratePlan"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	return o.engine.Plan(postProcessor, operation, report)
}

func (o *OtelGraphqlEngineV2) Resolve(resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error {
	var operationName = "ResolvePlan"
	ctx, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	resolveContext.Context = ctx
	return o.engine.Resolve(resolveContext, planResult, writer)
}

func (o *OtelGraphqlEngineV2) Teardown() {
}

func (o *OtelGraphqlEngineV2) InputValidation(operation *graphql.Request) error {
	var operationName = "InputValidation"
	_, span := o.tracerProvider.Tracer().Start(o.traceContext, operationName)
	defer span.End()
	return o.engine.InputValidation(operation)
}

func (o *OtelGraphqlEngineV2) Execute(inCtx context.Context, operation *graphql.Request, writer resolve.FlushWriter, options ...graphql.ExecutionOptionsV2) error {
	ctx, span := o.tracerProvider.Tracer().Start(inCtx, "GraphqlEngine")
	defer span.End()
	o.setContext(ctx)
	return o.rootExecutor.Execute(inCtx, operation, writer, options...)
}

func NewOtelGraphqlEngineV2(tracerProvider otel.TracerProvider, engine *graphql.ExecutionEngineV2) *OtelGraphqlEngineV2 {
	return &OtelGraphqlEngineV2{
		tracerProvider: tracerProvider,
		engine:         engine,
	}
}
