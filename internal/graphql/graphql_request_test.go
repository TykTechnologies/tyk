package graphql

import (
	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const sampleSchema = `
type Query {
  characters(filter: FilterCharacter, page: Int): Characters
  listCharacters(): [Characters]!
}

type Mutation {
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
