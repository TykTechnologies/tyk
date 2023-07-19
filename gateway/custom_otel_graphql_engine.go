package gateway

import (
	"context"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"
	"github.com/TykTechnologies/tyk/internal/otel"
	tyktrace "github.com/TykTechnologies/tyk/trace"
	"github.com/sirupsen/logrus"
	"sync"
)

type OtelGraphqlEngineV2 struct {
	mutex          sync.Mutex
	logger         *logrus.Entry
	spec           *APISpec
	spanContext    context.Context
	tracerProvider otel.TracerProvider

	engine graphql.CustomExecutionEngineV2
}

func (o *OtelGraphqlEngineV2) setContext(ctx context.Context) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.spanContext = ctx
}

func (o *OtelGraphqlEngineV2) Normalize(operation *graphql.Request) error {
	var operationName = "NormalizeRequest"
	if tyktrace.IsEnabled() {
		span, ctx := tyktrace.Span(o.spanContext, operationName)
		defer span.Finish()
		o.setContext(ctx)
	} else {
		ctx, span := o.tracerProvider.Tracer().Start(o.spanContext, operationName)
		defer span.End()
		o.setContext(ctx)
	}
	return o.engine.Normalize(operation)
}

func (o *OtelGraphqlEngineV2) ValidateForSchema(operation *graphql.Request) error {
	//TODO implement me
	panic("implement me")
}

func (o *OtelGraphqlEngineV2) Setup(ctx context.Context, postProcessor *postprocess.Processor, resolveContext *resolve.Context, operation *graphql.Request, options ...graphql.ExecutionOptionsV2) {
	//TODO implement me
	panic("implement me")
}

func (o *OtelGraphqlEngineV2) Plan(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) (plan.Plan, error) {
	//TODO implement me
	panic("implement me")
}

func (o *OtelGraphqlEngineV2) Resolve(resolveContext *resolve.Context, planResult plan.Plan, writer resolve.FlushWriter) error {
	//TODO implement me
	panic("implement me")
}

func (o *OtelGraphqlEngineV2) Teardown() {
	//TODO implement me
	panic("implement me")
}

func (o *OtelGraphqlEngineV2) InputValidation(operation *graphql.Request) error {
	//TODO implement me
	panic("implement me")
}

func NewOtelGraphqlEngineV2(tracerProvider otel.TracerProvider, engine graphql.CustomExecutionEngineV2) *OtelGraphqlEngineV2 {
	return &OtelGraphqlEngineV2{
		tracerProvider: tracerProvider,
		engine:         engine,
	}
}
