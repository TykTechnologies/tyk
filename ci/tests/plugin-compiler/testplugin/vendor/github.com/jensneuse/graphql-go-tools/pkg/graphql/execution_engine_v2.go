package graphql

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/subscription"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
	"github.com/jensneuse/graphql-go-tools/pkg/postprocess"
)

type EngineV2Configuration struct {
	schema        *Schema
	plannerConfig plan.Configuration
}

func NewEngineV2Configuration(schema *Schema) EngineV2Configuration {
	return EngineV2Configuration{
		schema: schema,
		plannerConfig: plan.Configuration{
			DefaultFlushInterval: 0,
			DataSources:          []plan.DataSourceConfiguration{},
			Fields:               plan.FieldConfigurations{},
		},
	}
}

func (e *EngineV2Configuration) AddDataSource(dataSource plan.DataSourceConfiguration) {
	e.plannerConfig.DataSources = append(e.plannerConfig.DataSources, dataSource)
}

func (e *EngineV2Configuration) SetDataSources(dataSources []plan.DataSourceConfiguration) {
	e.plannerConfig.DataSources = dataSources
}

func (e *EngineV2Configuration) AddFieldConfiguration(fieldConfig plan.FieldConfiguration) {
	e.plannerConfig.Fields = append(e.plannerConfig.Fields, fieldConfig)
}

func (e *EngineV2Configuration) SetFieldConfigurations(fieldConfigs plan.FieldConfigurations) {
	e.plannerConfig.Fields = fieldConfigs
}

type EngineResultWriter struct {
	buf           *bytes.Buffer
	flushCallback func(data []byte)
}

func NewEngineResultWriter() EngineResultWriter {
	return EngineResultWriter{
		buf: &bytes.Buffer{},
	}
}

func NewEngineResultWriterFromBuffer(buf *bytes.Buffer) EngineResultWriter {
	return EngineResultWriter{
		buf: buf,
	}
}

func (e *EngineResultWriter) SetFlushCallback(flushCb func(data []byte)) {
	e.flushCallback = flushCb
}

func (e *EngineResultWriter) Write(p []byte) (n int, err error) {
	return e.buf.Write(p)
}

func (e *EngineResultWriter) Read(p []byte) (n int, err error) {
	return e.buf.Read(p)
}

func (e *EngineResultWriter) Flush() {
	if e.flushCallback != nil {
		e.flushCallback(e.Bytes())
	}

	e.Reset()
}

func (e *EngineResultWriter) Len() int {
	return e.buf.Len()
}

func (e *EngineResultWriter) Bytes() []byte {
	return e.buf.Bytes()
}

func (e *EngineResultWriter) String() string {
	return e.buf.String()
}

func (e *EngineResultWriter) Reset() {
	e.buf.Reset()
}

func (e *EngineResultWriter) AsHTTPResponse(status int, headers http.Header) *http.Response {
	res := &http.Response{}
	res.Body = ioutil.NopCloser(e.buf)
	res.Header = headers
	res.StatusCode = status
	return res
}

type internalExecutionContext struct {
	resolveContext *resolve.Context
	postProcessor  *postprocess.Processor
}

func newInternalExecutionContext() *internalExecutionContext {
	return &internalExecutionContext{
		resolveContext: resolve.NewContext(context.Background()),
		postProcessor:  postprocess.DefaultProcessor(),
	}
}

func (e *internalExecutionContext) prepare(ctx context.Context, variables []byte, request resolve.Request) {
	e.setContext(ctx)
	e.setVariables(variables)
	e.setRequest(request)
}

func (e *internalExecutionContext) setRequest(request resolve.Request) {
	e.resolveContext.Request = request
}

func (e *internalExecutionContext) setContext(ctx context.Context) {
	e.resolveContext.Context = ctx
}

func (e *internalExecutionContext) setVariables(variables []byte) {
	e.resolveContext.Variables = variables
}

func (e *internalExecutionContext) reset() {
	e.resolveContext.Free()
}

type ExecutionEngineV2 struct {
	logger                       abstractlogger.Logger
	config                       EngineV2Configuration
	plannerPool                  sync.Pool
	resolver                     *resolve.Resolver
	internalExecutionContextPool sync.Pool
}

type ExecutionOptionsV2 func(ctx *internalExecutionContext)

func WithBeforeFetchHook(hook resolve.BeforeFetchHook) ExecutionOptionsV2 {
	return func(ctx *internalExecutionContext) {
		ctx.resolveContext.SetBeforeFetchHook(hook)
	}
}

func WithAfterFetchHook(hook resolve.AfterFetchHook) ExecutionOptionsV2 {
	return func(ctx *internalExecutionContext) {
		ctx.resolveContext.SetAfterFetchHook(hook)
	}
}

func NewExecutionEngineV2WithTriggerManagers(logger abstractlogger.Logger, engineConfig EngineV2Configuration, closer <- chan struct{}, triggerManagers ...*subscription.Manager) (*ExecutionEngineV2, error) {
	executionEngine, err := NewExecutionEngineV2(logger, engineConfig, closer)
	if err != nil {
		return nil, err
	}

	for _, triggerManager := range triggerManagers {
		executionEngine.WithTriggerManager(triggerManager)
	}

	return executionEngine, nil
}

func NewExecutionEngineV2(logger abstractlogger.Logger, engineConfig EngineV2Configuration, closer <- chan struct{}) (*ExecutionEngineV2, error) {
	return &ExecutionEngineV2{
		logger: logger,
		config: engineConfig,
		plannerPool: sync.Pool{
			New: func() interface{} {
				return plan.NewPlanner(engineConfig.plannerConfig, closer)
			},
		},
		resolver: resolve.New(),
		internalExecutionContextPool: sync.Pool{
			New: func() interface{} {
				return newInternalExecutionContext()
			},
		},
	}, nil
}

func (e *ExecutionEngineV2) WithTriggerManager(subManager *subscription.Manager) {
	e.resolver.RegisterTriggerManager(subManager)
}

func (e *ExecutionEngineV2) Execute(ctx context.Context, operation *Request, writer resolve.FlushWriter, options ...ExecutionOptionsV2) error {
	if !operation.IsNormalized() {
		result, err := operation.Normalize(e.config.schema)
		if err != nil {
			return err
		}

		if !result.Successful {
			return result.Errors
		}
	}

	execContext := e.getExecutionCtx()
	defer e.putExecutionCtx(execContext)

	execContext.prepare(ctx, operation.Variables, operation.request)

	for i := range options {
		options[i](execContext)
	}

	// Optimization: Hashing the operation and caching the postprocessed plan for
	// this specific operation will improve perfomance significantly.
	var report operationreport.Report
	planner := e.plannerPool.Get().(*plan.Planner)
	planResult := planner.Plan(&operation.document, &e.config.schema.document, operation.OperationName, &report)
	e.plannerPool.Put(planner)
	if report.HasErrors() {
		return errors.New(report.Error())
	}

	planResult = execContext.postProcessor.Process(planResult)

	var err error
	switch p := planResult.(type) {
	case *plan.SynchronousResponsePlan:
		err = e.resolver.ResolveGraphQLResponse(execContext.resolveContext, p.Response, nil, writer)
	case *plan.SubscriptionResponsePlan:
		err = e.resolver.ResolveGraphQLSubscription(execContext.resolveContext, &p.Response, writer)
	default:
		return errors.New("execution of operation is not possible")
	}

	return err
}

func (e *ExecutionEngineV2) getExecutionCtx() *internalExecutionContext {
	return e.internalExecutionContextPool.Get().(*internalExecutionContext)
}

func (e *ExecutionEngineV2) putExecutionCtx(ctx *internalExecutionContext) {
	ctx.reset()
	e.internalExecutionContextPool.Put(ctx)
}
