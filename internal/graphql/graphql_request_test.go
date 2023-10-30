package graphql

import (
	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const sampleSchema = `
schema {
  query: Query
  mutation: CustomMutation
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

func TestNewRequestFromBodySchema(t *testing.T) {
	rawRequest := `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}"}`

	req, err := NewRequestFromBodySchema(rawRequest, sampleSchema)
	assert.NoError(t, err)
	assert.NotNil(t, req.schema)
	assert.NotNil(t, req.requestDoc)
	assert.Equal(t, req.operationRef, ast.InvalidRef)
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
			req, err := NewRequestFromBodySchema(test.request, sampleSchema)
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
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			req, err := NewRequestFromBodySchema(test.request, sampleSchema)
			require.NoError(t, err)
			gotten := req.TypesAndFields()
			assert.Equal(t, test.expectedResponse, gotten)
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
			req, err := NewRequestFromBodySchema(test.request, sampleSchema)
			require.NoError(t, err)
			gotten := req.SchemaRootOperationTypeName()
			assert.Equal(t, test.expectedResponse, gotten)
		})
	}
}
