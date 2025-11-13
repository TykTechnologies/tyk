package graphengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jensneuse/abstractlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type engineV1Mocks struct {
	controller             *gomock.Controller
	requestProcessor       *MockGraphQLRequestProcessor
	complexityChecker      *MockComplexityChecker
	granularAccessChecker  *MockGranularAccessChecker
	reverseProxyPreHandler *MockReverseProxyPreHandler
}

func TestEngineV1_HasSchema(t *testing.T) {
	t.Run("should be true if engine has a schema", func(t *testing.T) {
		engine := EngineV1{
			Schema: &graphql.Schema{},
		}
		assert.True(t, engine.HasSchema())
	})
	t.Run("should be false if engine has no schema", func(t *testing.T) {
		engine := EngineV1{
			Schema: nil,
		}
		assert.False(t, engine.HasSchema())
	})
}

func TestEngineV1_ProcessAndStoreGraphQLRequest(t *testing.T) {
	t.Run("should return error and Bad Request if it can't parse the gql request", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte("invalid gql request")))
		require.NoError(t, err)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(nil, request)
		assert.Equal(t, 400, statusCode)
		assert.Error(t, err)
	})

	t.Run("should return no error and success if no error occurs", func(t *testing.T) {
		var expectedGraphQLRequest *graphql.Request
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		engine.ctxStoreRequestFunc = func(r *http.Request, gqlRequest *graphql.Request) {
			expectedGraphQLRequest = gqlRequest
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := &httptest.ResponseRecorder{}

		mocks.requestProcessor.EXPECT().ProcessRequest(gomock.Eq(request.Context()), gomock.Eq(recorder), gomock.Eq(request)).
			Return(nil, 200)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
		assert.Equal(t, expectedGraphQLRequest, &graphql.Request{
			Query: "query { hello }",
		})
	})
}

func TestEngineV1_ProcessGraphQLComplexity(t *testing.T) {
	t.Run("should return error and status code 500 if the underlying complexity checker returns an internal fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonInternalError)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and status code 403 if the underlying complexity checker returns fail reason depth limit exceeded", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonDepthLimitExceeded)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 403, statusCode)
	})

	t.Run("should return no error and status code 200 if the underlying complexity checker returns no fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonNone)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func TestEngineV1_ProcessGraphQLGranularAccess(t *testing.T) {
	t.Run("should return error and status code 500 if the underlying granular access checker returns an internal fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason: GranularAccessFailReasonInternalError,
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and status code 400 if the underlying granular access checker returns a validation fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason:      GranularAccessFailReasonValidationError,
				ValidationError: errors.New("failed validation"),
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
	})

	t.Run("should return no error and status code 200 if the underlying granular access checker returns no fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason: GranularAccessFailReasonNone,
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func TestEngineV1_HandleReverseProxy(t *testing.T) {
	t.Run("should return error if reverse proxy pre handler returns error", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeNone, errors.New("error"))

		_, hijacked, err := engine.HandleReverseProxy(params)
		assert.Error(t, err)
		assert.False(t, hijacked)
	})

	t.Run("should return error if execution engine is nil", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeGraphEngine, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{} // return empty request to avoid nil pointer dereference. We don't care about the request in this test
		}

		engine.ExecutionEngine = nil

		_, hijacked, err := engine.HandleReverseProxy(params)
		assert.Error(t, err)
		assert.False(t, hijacked)
	})

	t.Run("should execute graphql introspection if reverse proxy pre handler returns reverse proxy type introspection", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeIntrospection, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{} // return empty request to avoid nil pointer dereference. We don't care about the request in this test
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(result.Body)

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Equal(t, 200, result.StatusCode)
		assert.Equal(t, testIntrospectionResultEngineV1, body.String())
	})

	t.Run("should handover request to graphql execution engine if reverse proxy pre handler returns reverse proxy type graph engine", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"hello": "world"}`))
		}))
		t.Cleanup(server.Close)

		engine, mocks := newTestEngineV1(t, withTargetURLTestEngineV1(server.URL))
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeGraphEngine, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query: "query { hello }",
			}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(result.Body)

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Equal(t, 200, result.StatusCode)
		assert.Equal(t, `{"data":{"hello":"world"}}`, body.String())
	})

	t.Run("should return error if reverse proxy pre handler returns proxy type preflight and execution mode is NOT proxy only", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t, withExecutionModeTestEngineV1(apidef.GraphQLExecutionModeSubgraph))
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest:      &http.Request{},
			IsCORSPreflight: true,
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypePreFlight, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query: "query { hello }",
			}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		var body bytes.Buffer
		if result != nil {
			_, _ = body.ReadFrom(result.Body)
		}

		assert.Error(t, err)
		assert.False(t, hijacked)
		assert.Nil(t, result)
	})

	t.Run("should return successful if reverse proxy pre handler returns proxy type preflight and execution mode is proxy only", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t, withExecutionModeTestEngineV1(apidef.GraphQLExecutionModeProxyOnly))
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest:      &http.Request{},
			IsCORSPreflight: true,
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypePreFlight, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		var body bytes.Buffer
		if result != nil {
			_, _ = body.ReadFrom(result.Body)
		}

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Nil(t, result)
	})

}

type testEngineV1Options struct {
	targetURL     string
	executionMode apidef.GraphQLExecutionMode
}

type testEngineV1Option func(*testEngineV1Options)

func withTargetURLTestEngineV1(targetURL string) testEngineV1Option {
	return func(options *testEngineV1Options) {
		options.targetURL = targetURL
	}
}

func withExecutionModeTestEngineV1(executionMode apidef.GraphQLExecutionMode) testEngineV1Option {
	return func(options *testEngineV1Options) {
		options.executionMode = executionMode
	}
}

func newTestEngineV1(t *testing.T, options ...testEngineV1Option) (*EngineV1, engineV1Mocks) {
	t.Helper()

	definedOptions := testEngineV1Options{}
	for _, option := range options {
		option(&definedOptions)
	}

	ctrl := gomock.NewController(t)
	mocks := engineV1Mocks{
		controller:             ctrl,
		requestProcessor:       NewMockGraphQLRequestProcessor(ctrl),
		complexityChecker:      NewMockComplexityChecker(ctrl),
		granularAccessChecker:  NewMockGranularAccessChecker(ctrl),
		reverseProxyPreHandler: NewMockReverseProxyPreHandler(ctrl),
	}

	apiDefinition := generateApiDefinitionEngineV1(definedOptions.targetURL, definedOptions.executionMode)
	gqlTools := graphqlGoToolsV1{}
	schema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	executionEngine, err := gqlTools.createExecutionEngine(createExecutionEngineV1Params{
		logger: abstractlogger.NoopLogger,
		apiDef: apiDefinition,
		schema: schema,
	})

	engine := &EngineV1{
		ExecutionEngine:         executionEngine,
		Schema:                  schema,
		ApiDefinition:           apiDefinition,
		logger:                  abstractlogger.NoopLogger,
		graphqlRequestProcessor: mocks.requestProcessor,
		complexityChecker:       mocks.complexityChecker,
		granularAccessChecker:   mocks.granularAccessChecker,
		reverseProxyPreHandler:  mocks.reverseProxyPreHandler,
	}

	return engine, mocks
}

func generateApiDefinitionEngineV1(targetURL string, executionMode apidef.GraphQLExecutionMode) *apidef.APIDefinition {
	return &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:          true,
			ExecutionMode:    executionMode,
			Version:          apidef.GraphQLConfigVersion1,
			Schema:           testSchemaEngineV1,
			LastSchemaUpdate: nil,
			TypeFieldConfigurations: []datasource.TypeFieldConfiguration{
				{
					TypeName:  "Query",
					FieldName: "hello",
					Mapping:   nil,
					DataSource: datasource.SourceConfig{
						Name: "HTTPJSONDataSource",
						Config: json.RawMessage(`{
						  "url": "` + targetURL + `",
						  "method": "GET",
						  "body": "",
						  "headers": [],
						  "default_type_name": "String",
						  "status_code_type_name_mappings": [
							{
							  "status_code": 200,
							  "type_name": ""
							}
						  ]
						}`),
					},
					DataSourcePlannerFactory: nil,
				},
			},
		},
	}
}

var testSchemaEngineV1 = `
type Query {
	hello: String
	helloName(name: String!): String
}
`

var testSchemaNestedEngineV1 = `
type Query {
	countries: [Country]
}

type Country {
	continent: Continent
}

type Continent {
	countries: [Country]
}`

var testIntrospectionQuery = `query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`

var testIntrospectionResultEngineV1 = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"kind":"OBJECT","name":"Query","description":"","fields":[{"name":"hello","description":"","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null},"isDeprecated":false,"deprecationReason":null},{"name":"helloName","description":"","args":[{"name":"name","description":"","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"String","ofType":null}},"defaultValue":null}],"type":{"kind":"SCALAR","name":"String","ofType":null},"isDeprecated":false,"deprecationReason":null}],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]},{"kind":"SCALAR","name":"Int","description":"The 'Int' scalar type represents non-fractional signed whole numeric values. Int can represent values between -(2^31) and 2^31 - 1.","fields":[],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]},{"kind":"SCALAR","name":"Float","description":"The 'Float' scalar type represents signed double-precision fractional values as specified by [IEEE 754](http://en.wikipedia.org/wiki/IEEE_floating_point).","fields":[],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]},{"kind":"SCALAR","name":"String","description":"The 'String' scalar type represents textual data, represented as UTF-8 character sequences. The String type is most often used by GraphQL to represent free-form human-readable text.","fields":[],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]},{"kind":"SCALAR","name":"Boolean","description":"The 'Boolean' scalar type represents 'true' or 'false' .","fields":[],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]},{"kind":"SCALAR","name":"ID","description":"The 'ID' scalar type represents a unique identifier, often used to refetch an object or as key for a cache. The ID type appears in a JSON response as a String; however, it is not intended to be human-readable. When expected as an input type, any string (such as '4') or integer (such as 4) input value will be accepted as an ID.","fields":[],"inputFields":[],"interfaces":[],"enumValues":[],"possibleTypes":[]}],"directives":[{"name":"include","description":"Directs the executor to include this field or fragment only when the argument is true.","locations":["FIELD","FRAGMENT_SPREAD","INLINE_FRAGMENT"],"args":[{"name":"if","description":"Included when true.","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Boolean","ofType":null}},"defaultValue":null}],"isRepeatable":false},{"name":"skip","description":"Directs the executor to skip this field or fragment when the argument is true.","locations":["FIELD","FRAGMENT_SPREAD","INLINE_FRAGMENT"],"args":[{"name":"if","description":"Skipped when true.","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Boolean","ofType":null}},"defaultValue":null}],"isRepeatable":false},{"name":"deprecated","description":"Marks an element of a GraphQL schema as no longer supported.","locations":["FIELD_DEFINITION","ENUM_VALUE"],"args":[{"name":"reason","description":"Explains why this element was deprecated, usually also including a suggestion\n    for how to access supported similar data. Formatted in\n    [Markdown](https://daringfireball.net/projects/markdown/).","type":{"kind":"SCALAR","name":"String","ofType":null},"defaultValue":"\"No longer supported\""}],"isRepeatable":false}]}}}
`
