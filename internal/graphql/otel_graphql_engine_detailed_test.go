package graphql

import (
	"context"
	"errors"
	"os"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/logger"
	"github.com/TykTechnologies/tyk/internal/otel"
)

var request = graphql.Request{
	Query: `{
  country(code: "NG"){
    name
  }
}`,
}

var namedRequest = graphql.Request{
	OperationName: "MyQuery",
	Query: `query MyQuery {
  country(code: "TR"){
    name
  }
}`,
}

var tracerProvider otel.TracerProvider

func TestMain(m *testing.M) {
	//use noop tracer exporter
	tracerProvider = otel.InitOpenTelemetry(context.Background(), logger.GetLogger(), &otel.OpenTelemetry{
		Enabled:  true,
		Exporter: "invalid",
	}, "test", "test", false, "", false, []string{})
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestOtelGraphqlEngineV2Detailed_Normalize(t *testing.T) {
	t.Run("normalize always returns nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)

		result := engine.Normalize(&request)
		assert.NoError(t, result)
	})
}

func TestOtelGraphqlEngineV2Detailed_Setup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockExecutor := NewMockExecutionEngineI(ctrl)
	mockExecutor.EXPECT().Setup(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
	engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
	assert.NoError(t, err)
	engine.SetContext(context.Background())

	engine.Setup(context.Background(), nil, nil, &request)
	assert.NoError(t, err)
}

func TestOtelGraphqlEngineV2Detailed_InputValidation(t *testing.T) {
	t.Run("successfully validate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().InputValidation(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.InputValidation(&request)
		assert.NoError(t, err)
	})

	t.Run("fail input validation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().InputValidation(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.InputValidation(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})
}

func TestOtelGraphqlEngineV2Detailed_ValidateForSchema(t *testing.T) {
	t.Run("validate for schema always returns nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.ValidateForSchema(&request)
		assert.NoError(t, err)
	})
}

func TestOtelGraphqlEngineV2Detailed_Plan(t *testing.T) {
	t.Run("failed to generate plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		var report operationreport.Report
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, nil).Do(
			func(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) {
				report.AddExternalError(operationreport.ExternalError{Message: "error creating plan"})
			})

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.NoError(t, err)
		assert.True(t, report.HasErrors(), "expected error from operation report, got none")
	})

	t.Run("successfully generate plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var report operationreport.Report
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.NoError(t, err)
		assert.False(t, report.HasErrors())
	})

	t.Run("return error generating plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var report operationreport.Report
		expectedErr := errors.New("error generating plan")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, expectedErr)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.ErrorIs(t, expectedErr, err)
		assert.False(t, report.HasErrors())
	})
}

func TestOtelGraphqlEngineV2Detailed_Resolve(t *testing.T) {
	t.Run("successfully resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Resolve(gomock.Any(), gomock.Any(), nil).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Resolve(&resolve.Context{}, nil, nil)
		assert.NoError(t, err)
	})

	t.Run("fail resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectedErr := errors.New("error resolving request")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Resolve(gomock.Any(), gomock.Any(), nil).MaxTimes(1).Return(expectedErr)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Resolve(&resolve.Context{}, nil, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestOtelGraphqlEngineV2Detailed_Execute(t *testing.T) {
	t.Run("successfully execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &request, nil).MaxTimes(1).Return(nil)
		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		engine.executor = mockExecutor
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.NoError(t, err)
	})

	t.Run("fail execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectedErr := errors.New("error executing request")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &request, nil).MaxTimes(1).Return(expectedErr)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.executor = mockExecutor
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

type tracerProviderWrapper struct {
	provider       tyktrace.Provider
	spanAttributes map[string][]attribute.KeyValue
}

func newTracerProviderWrapper(provider tyktrace.Provider) *tracerProviderWrapper {
	return &tracerProviderWrapper{
		provider:       provider,
		spanAttributes: make(map[string][]attribute.KeyValue),
	}
}

func (t *tracerProviderWrapper) Shutdown(ctx context.Context) error {
	return t.provider.Shutdown(ctx)
}

func (t *tracerProviderWrapper) Tracer() tyktrace.Tracer {
	return &tracerWrapper{
		tracer:         t.provider.Tracer(),
		spanAttributes: t.spanAttributes,
	}
}

func (t *tracerProviderWrapper) Type() string {
	return t.provider.Type()
}

var _ tyktrace.Provider = (*tracerProviderWrapper)(nil)

type tracerWrapper struct {
	tracer         tyktrace.Tracer
	spanAttributes map[string][]attribute.KeyValue
}

func (t *tracerWrapper) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	tracerCtx, span := t.tracer.Start(ctx, spanName, opts...)
	return tracerCtx, &spanWrapper{
		name:       spanName,
		span:       span,
		attributes: t.spanAttributes,
	}
}

var _ tyktrace.Tracer = (*tracerWrapper)(nil)

type spanWrapper struct {
	name       string
	span       trace.Span
	attributes map[string][]attribute.KeyValue
}

func (s *spanWrapper) End(options ...trace.SpanEndOption) {
	s.span.End(options...)
}

func (s *spanWrapper) AddEvent(name string, options ...trace.EventOption) {
	s.span.AddEvent(name, options...)
}

func (s *spanWrapper) IsRecording() bool {
	return s.span.IsRecording()
}

func (s *spanWrapper) RecordError(err error, options ...trace.EventOption) {
	s.span.RecordError(err, options...)
}

func (s *spanWrapper) SpanContext() trace.SpanContext {
	return s.span.SpanContext()
}

func (s *spanWrapper) SetStatus(code codes.Code, description string) {
	s.span.SetStatus(code, description)
}

func (s *spanWrapper) SetName(name string) {
	s.span.SetName(name)
}

func (s *spanWrapper) SetAttributes(kv ...attribute.KeyValue) {
	s.span.SetAttributes(kv...)
	s.attributes[s.name] = append(s.attributes[s.name], kv...)
}

func (s *spanWrapper) TracerProvider() trace.TracerProvider {
	return s.span.TracerProvider()
}

var _ trace.Span = (*spanWrapper)(nil)
