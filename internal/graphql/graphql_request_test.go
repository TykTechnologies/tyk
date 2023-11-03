package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/tyk-pump/analytics"
)

// TODO fix when input named character
const validSchema = `
schema {
  query: Que
  mutation: CustomMutation
}

type Que {
  characters(filter: FilterCharacter, page: Int): Characters
  listCharacters(): [Characters]!
}

type CustomMutation {
  changeCharacter(): String
}

type Subscription {
  listenCharacter(): Characters
}
input FilterCharacter {
  name: String
  status: String
  species: String
  type: String
  gender: String! = "M"
}
type Characters {
  info: Info
  secondInfo: String
  results: [Character]
}
type Info {
  count: Int
  next: Int
  pages: Int
  prev: Int
}
type Character {
  gender: String
  id: ID
  name: String
}

type EmptyType{
}
`

const invalidSchema = `
schema {
  query: Query
  mutation: CustomMutation
}

input Characters{
}

type Query {
  characters(filter: FilterCharacter, page: Int): Characters
  listCharacters(): [Characters]!
}

type CustomMutation {
  changeCharacter(): String
}

type Subscription {
  listenCharacter(): Characters
}
input FilterCharacter {
  name: String
  status: String
  species: String
  type: String
  gender: String! = "M"
}
type Characters {
  info: Info
  secondInfo: String
  results: [Character]
}
type Info {
  count: Int
  next: Int
  pages: Int
  prev: Int
}
type Character {
  gender: String
  id: ID
  name: String
}

type EmptyType{
}
`

const noSchema = `
schema {
  query: Query
  mutation: CustomMutation
`

func TestGraphStatsExtractionVisitor_ExtractStats(t *testing.T) {
	testCases := []struct {
		name               string
		request            string
		schema             string
		expectedFields     map[string][]string
		expectedRootFields []string
	}{
		{
			name:    "should successfully parse",
			schema:  validSchema,
			request: `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`,
			expectedFields: map[string][]string{
				"Characters": {"info"},
				"Info":       {"count"},
			},
			expectedRootFields: []string{"characters"},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			extractor := NewGraphStatsExtractor()
			stats, err := extractor.ExtractStats(test.request, test.schema)
			require.NoError(t, err)
			assert.Equal(t, test.expectedFields, stats.Types)
			assert.Equal(t, test.expectedRootFields, stats.RootFields)

		})
	}
}

func TestNewRequestFromBodySchema(t *testing.T) {
	testCases := []struct {
		name        string
		expectError bool
		request     string
		schema      string
	}{
		{
			name:        "successfully generate request",
			expectError: false,
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`,
			schema:      validSchema,
		},
		{
			name:        "error for invalid request",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      counta\n    }\n  }\n}"}`,
			expectError: true,
			schema:      validSchema,
		},
		{
			name:        "error from invalid schema",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`,
			expectError: true,
			schema:      invalidSchema,
		},
		{
			name:        "error from invalid syntax in request",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  \n}"}`,
			expectError: true,
			schema:      validSchema,
		},
		{
			name:        "error from invalid json",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  \n}`,
			expectError: true,
			schema:      validSchema,
		},
		{
			name:        "error from incomplete schema",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`,
			expectError: true,
			schema:      noSchema,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, test.schema)
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, req.schema)
				assert.NotNil(t, req.requestDoc)
				assert.Equal(t, req.operationRef, ast.InvalidRef)
			}
		})
	}
	t.Run("error from incomplete schema", func(t *testing.T) {
		rawRequest := `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`
		_, err := NewRequestFromBodySchema(rawRequest, noSchema)
		assert.Error(t, err)
	})
}

func TestGraphRequest_RootFields(t *testing.T) {
	testCases := []struct {
		name             string
		request          string
		expectedResponse []string
	}{
		{
			name:             "should return root fields",
			request:          `{"query":"query {\n  characters(filter: {}) {\n    \n  }\n}\n\n"}`,
			expectedResponse: []string{"characters"},
		},
		{
			name:             "should return multiple root fields",
			request:          `{"query":"query {\n  characters(filter: {}) {\n    info {\n      count\n    }\n  }\n  listCharacters {\n    secondInfo\n  }\n}\n\n"}`,
			expectedResponse: []string{"characters", "listCharacters"},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, validSchema)
			require.NoError(t, err)
			gotten := req.RootFields()
			assert.Equal(t, test.expectedResponse, gotten)
		})
	}
}

func TestGraphRequest_TypesAndFields(t *testing.T) {
	testCases := []struct {
		name             string
		request          string
		expectedResponse map[string][]string
	}{
		{
			name:    "should get all types and fields single",
			request: `{"query":"query {\n  characters {\n    info {\n      count\n    }\n  }\n}"}`,
			expectedResponse: map[string][]string{
				"Characters": []string{"info"},
				"Info":       []string{"count"},
			},
		},
		{
			request: `{"query":"mutation second{\n changeCharacter\n}\n\n query main{\n characters{\n info{\n count\n }\n }\n}","operationName":"main"}`,
			name:    "should get all types for multiple operations",
			expectedResponse: map[string][]string{
				"Characters": []string{"info"},
				"Info":       []string{"count"},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, validSchema)
			require.NoError(t, err)
			gotten := req.TypesAndFields()
			assert.Equal(t, test.expectedResponse, gotten)
		})
	}
}

func TestGraphRequest_GraphErrors(t *testing.T) {
	testCases := []struct {
		name     string
		response string
		hasError bool
		expected []string
	}{
		{
			name:     "only errors in response",
			response: `{"errors":[{"message":"Name for character with ID 1002 could not be fetched.","locations":[{"line":6,"column":7}],"path":["hero","heroFriends",1,"name"]}]}`,
			expected: []string{"Name for character with ID 1002 could not be fetched."},
		},
		{
			name:     "invalid json in errors array",
			response: `{"errors":[{"message:"Name for character with ID 1002 could not be fetched.","locations":[{"line":6,"column":7}],"path":["hero","heroFriends",1,"name"]}]}`,
			expected: nil,
			hasError: true,
		},
		{
			name:     "error and data in response",
			response: `{"errors":[{"message":"Name for character with ID 1002 could not be fetched.","locations":[{"line":6,"column":7}],"path":["hero","heroFriends",1,"name"]}],"data":{"hero":{"name":"R2-D2","heroFriends":[{"id":"1000","name":"Luke Skywalker"},{"id":"1002","name":null},{"id":"1003","name":"Leia Organa"}]}}}`,
			expected: []string{"Name for character with ID 1002 could not be fetched."},
		},
		{
			name:     "no error in json",
			response: `{"data":{"hero":{"name":"R2-D2","heroFriends":[{"id":"1000","name":"Luke Skywalker"},{"id":"1002","name":null},{"id":"1003","name":"Leia Organa"}]}}}`,
			expected: nil,
		},
		{
			name:     "invalid json",
			response: `{"errors:[{"message":"Name for character with ID 1002 could not be fetched.","locations":[{"line":6,"column":7}],"path":["hero","heroFriends",1,"name"]}]}`,
			expected: nil,
		},
	}

	request := `{"query":"query {\n  characters(filter: {}) {\n    \n  }\n}\n\n"}`
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(request, validSchema)
			require.NoError(t, err)
			gotten, err := req.GraphErrors([]byte(test.response))
			if test.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expected, gotten)
		})
	}
}

func TestGraphRequest_OperationType(t *testing.T) {
	testCases := []struct {
		name     string
		request  string
		expected analytics.GraphQLOperations
	}{
		{
			name:     "should return query",
			request:  `{"query":"query {\n  characters(filter: {}) {\n    \n  }\n}\n\n"}`,
			expected: analytics.OperationQuery,
		},
		{
			name:     "should return mutation",
			request:  `{"query":"mutation {\n  changeCharacter\n}"}`,
			expected: analytics.OperationMutation,
		},
		{
			name:     "should return subscription",
			request:  `{"query":"subscription {\n  listenCharacter {\n    secondInfo\n  }\n}"}`,
			expected: analytics.OperationSubscription,
		},
		{
			name:     "multiple operation should return mutation",
			request:  `{"query":"query {\n  characters(filter: {}) {\n    secondInfo\n  }\n}\n\nmutation test{\n  changeCharacter\n}","operationName":"test"}`,
			expected: analytics.OperationMutation,
		},
		{
			name:     "non existent operation",
			request:  `{"query":"query {\n  characters(filter: {}) {\n    secondInfo\n  }\n}\n\nmutation test{\n  changeCharacter\n}","operationName":"testa"}`,
			expected: analytics.OperationUnknown,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, validSchema)
			require.NoError(t, err)
			gotten := req.OperationType()
			assert.Equal(t, test.expected, gotten)
		})
	}
}

func TestGraphRequest_SchemaRootOperationTypeName(t *testing.T) {
	testCases := []struct {
		name             string
		request          string
		expectedResponse string
	}{
		{
			name:             "should return query",
			request:          `{"query":"query {\n  characters(filter: {}) {\n    \n  }\n}\n\n"}`,
			expectedResponse: "Query",
		},
		{
			name:             "should return mutation",
			request:          `{"query":"mutation {\n  changeCharacter\n}"}`,
			expectedResponse: "CustomMutation",
		},
		{
			name:             "should return subscription",
			request:          `{"query":"subscription {\n  listenCharacter {\n    secondInfo\n  }\n}"}`,
			expectedResponse: "Subscription",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, validSchema)
			require.NoError(t, err)
			gotten := req.schemaRootOperationTypeName()
			assert.Equal(t, test.expectedResponse, gotten)
		})
	}
}
