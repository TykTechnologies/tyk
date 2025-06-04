package graphql

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		name        string
		request     string
		response    string
		schema      string
		expectError bool
		expected    analytics.GraphQLStats
	}{
		{
			name:     "should successfully parse",
			schema:   validSchema,
			request:  `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      count\n    }\n  }\n}","variables":{"in":"hello"}}`,
			response: `{"errors":[{"message":"Name for character with ID 1002 could not be fetched.","locations":[{"line":6,"column":7}],"path":["hero","heroFriends",1,"name"]}]}`,
			expected: analytics.GraphQLStats{
				Types: map[string][]string{
					"Characters": {"info"},
					"Info":       {"count"},
				},
				RootFields:    []string{"characters"},
				OperationType: analytics.OperationQuery,
				HasErrors:     true,
				Errors: []analytics.GraphError{
					{
						Message: "Name for character with ID 1002 could not be fetched.",
					},
				},
				IsGraphQL: true,
				Variables: `{"in":"hello"}`,
			},
		},
		{
			name:        "error for invalid request",
			request:     `{"query":"query{\n  characters(filter: {\n    \n  }){\n    info{\n      counta\n    }\n  }\n}"}`,
			expectError: true,
			schema:      validSchema,
		},
		{
			name:        "error for invalid schema",
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
		{
			name:    "should return multiple root fields",
			request: `{"query":"query {\n  characters(filter: {}) {\n    info {\n      count\n    }\n  }\n  listCharacters {\n    secondInfo\n  }\n}\n\n"}`,
			expected: analytics.GraphQLStats{
				RootFields: []string{"listCharacters", "characters"},
				Types: map[string][]string{
					"Characters": {"info", "secondInfo"},
					"Info":       {"count"},
				},
				IsGraphQL:     true,
				OperationType: analytics.OperationQuery,
			},
			schema: validSchema,
		},
		{
			request: `{"query":"mutation second{\n changeCharacter\n}\n\n query main{\n characters{\n info{\n count\n }\n }\n}","operationName":"main"}`,
			name:    "should get all types for multiple operations",
			expected: analytics.GraphQLStats{
				Types: map[string][]string{
					"Characters": {"info"},
					"Info":       {"count"},
				},
				RootFields:    []string{"characters"},
				OperationType: analytics.OperationQuery,
				IsGraphQL:     true,
				HasErrors:     false,
			},
			schema: validSchema,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			extractor := NewGraphStatsExtractor()
			stats, err := extractor.ExtractStats(test.request, test.response, test.schema)
			if test.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, stats.IsGraphQL)
			if diff := cmp.Diff(test.expected, stats, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Fatal(diff)
			}
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

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			extractor := NewGraphStatsExtractor()
			gotten, err := extractor.GraphErrors([]byte(test.response))
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
			extractor := NewGraphStatsExtractor()
			_, err := extractor.ExtractStats(test.request, "", validSchema)
			require.NoError(t, err)
			gotten := extractor.AnalyticsOperationTypes()
			assert.Equal(t, test.expected, gotten)
		})
	}
}
