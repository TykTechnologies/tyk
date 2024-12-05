package graphql

import (
	"context"
	"errors"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"

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

var schema *graphql.Schema

func TestMain(m *testing.M) {
	//use noop tracer exporter
	tracerProvider = otel.InitOpenTelemetry(context.Background(), logger.GetLogger(), &otel.OpenTelemetry{
		Enabled:  true,
		Exporter: "invalid",
	}, "test", "test", false, "", false, []string{})
	var err error
	schema, err = graphql.NewSchemaFromString(testSchema)
	if err != nil {
		log.Fatal(err)
	}
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestOtelGraphqlEngineV2Detailed_Normalize(t *testing.T) {
	t.Run("successfully normalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Normalize(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		result := request.IsNormalized()
		assert.False(t, result)

		err = engine.Normalize(&request)
		assert.NoError(t, err)
	})

	t.Run("fail normalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Normalize(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Normalize(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")
	})

	t.Run("already normalized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Normalize(gomock.Any()).MaxTimes(1).Return(nil)

		normalizeRequest, err := request.Normalize(schema)
		assert.NoError(t, err)
		assert.True(t, normalizeRequest.Successful)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		result := request.IsNormalized()
		assert.True(t, result)

		err = engine.Normalize(&request)
		assert.NoError(t, err)
	})
}

func TestOtelGraphqlEngineV2Detailed_Setup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockExecutor := NewMockExecutionEngineI(ctrl)
	mockExecutor.EXPECT().Setup(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
	engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.InputValidation(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})
}

func TestOtelGraphqlEngineV2Detailed_ValidateForSchema(t *testing.T) {
	t.Run("successfully validate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		result := request.IsValidated(schema)
		assert.False(t, result)

		err = engine.ValidateForSchema(&request)
		assert.NoError(t, err)
	})

	t.Run("fail validation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.ValidateForSchema(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})

	t.Run("already validated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(nil)

		validateSchema, err := request.ValidateForSchema(schema)
		assert.NoError(t, err)
		assert.True(t, validateSchema.Valid)

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		result := request.IsValidated(schema)
		assert.True(t, result)

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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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
		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
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

		engine, err := NewOtelGraphqlEngineV2Detailed(tracerProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.executor = mockExecutor
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestOtelGraphqlEngineV2Detailed_ValidateForSchema_SemanticConventionAttributes(t *testing.T) {
	checkStringAttribute := func(attributes []attribute.KeyValue, name attribute.Key, expectedValue string) {
		for _, attr := range attributes {
			if attr.Key == name {
				assert.Equal(t, attr.Value.AsString(), expectedValue)
				return
			}
		}
		assert.Failf(t, "attribute not found", string(name))
	}

	t.Run("successfully validate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(nil)

		wrappedTraceProvider := newTracerProviderWrapper(tracerProvider)
		engine, err := NewOtelGraphqlEngineV2Detailed(wrappedTraceProvider, mockExecutor, schema)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.ValidateForSchema(&namedRequest)
		assert.NoError(t, err)

		attributes := wrappedTraceProvider.spanAttributes["ValidateRequest"]
		assert.NotNil(t, attributes)

		checkStringAttribute(attributes, semconv.GraphQLOperationNameKey, namedRequest.OperationName)
		checkStringAttribute(attributes, semconv.GraphQLOperationTypeKey, "query")
		checkStringAttribute(attributes, semconv.GraphQLDocumentKey, namedRequest.Query)

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

func (s *spanWrapper) AddLink(link trace.Link) {
	s.span.AddLink(link)
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

var testSchema = `directive @cacheControl(maxAge: Int, scope: CacheControlScope) on FIELD_DEFINITION | OBJECT | INTERFACE

schema {
query: Query
}

interface CodeType {
code: ID!
}

interface CodeNameType implements CodeType {
code: ID!
name: String!
}

enum CacheControlScope {
PUBLIC
PRIVATE
}

type Continent implements CodeNameType & CodeType {
code: ID!
name: String!
countries: [Country!]!
}

input ContinentFilterInput {
code: StringQueryOperatorInput
}

type Country implements CodeNameType & CodeType {
code: ID!
name: String!
native: String!
phone: String!
continent: Continent!
capital: String
currency: String
languages: [Language!]!
emoji: String!
emojiU: String!
states: [State!]!
}

input CountryFilterInput {
code: StringQueryOperatorInput
currency: StringQueryOperatorInput
continent: StringQueryOperatorInput
}

type Language {
code: ID!
name: String
native: String
rtl: Boolean!
}

input LanguageFilterInput {
code: StringQueryOperatorInput
}

type Query {
continents(filter: ContinentFilterInput): [Continent!]!
continent(code: ID!): Continent
countries(filter: CountryFilterInput): [Country!]!
country(code: ID!): Country
languages(filter: LanguageFilterInput): [Language!]!
language(code: ID!): Language
codeType: CodeType!
}

type State {
code: String
name: String!
country: Country!
}

input StringQueryOperatorInput {
eq: String
ne: String
in: [String]
nin: [String]
regex: String
glob: String
}

"""The Upload scalar type represents a file upload."""
scalar Upload`
