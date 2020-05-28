package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/test"
)

func TestGraphQL(t *testing.T) {
	g := StartTest()
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
	})[0]

	t.Run("Bad schema", func(t *testing.T) {
		spec.GraphQL.GraphQLAPI.Schema = "query: Query"
		LoadAPI(spec)

		_, _ = g.Run(t, test.TestCase{BodyMatch: "there was a problem proxying the request", Code: http.StatusInternalServerError})
	})

	spec.GraphQL.GraphQLAPI.Schema = "schema { query: Query } type Query { hello: word } type word { numOfLetters: Int }"
	LoadAPI(spec)

	t.Run("Empty request shouldn't be unmarshalled", func(t *testing.T) {
		emptyRequest := ``

		_, _ = g.Run(t, test.TestCase{Data: emptyRequest, BodyMatch: gql.ErrEmptyRequest.Error(), Code: http.StatusBadRequest})
	})

	t.Run("Invalid query should fail", func(t *testing.T) {
		request := gql.Request{
			OperationName: "Goodbye",
			Variables:     nil,
			Query:         "query Goodbye { goodbye }",
		}

		_, _ = g.Run(t, test.TestCase{Data: request, Code: http.StatusBadRequest})
	})

	t.Run("Introspection query should successfully work", func(t *testing.T) {
		request := gql.Request{
			OperationName: "IntrospectionQuery",
			Variables:     nil,
			Query:         gqlIntrospectionQuery,
		}

		_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: "__schema", Code: http.StatusOK})
	})

	spec.UseKeylessAccess = false
	LoadAPI(spec)

	pID := CreatePolicy(func(p *user.Policy) {
		p.MaxQueryDepth = 1
		p.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
			},
		}
	})

	policyAppliedSession, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	directSession, directKey := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = 1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
			},
		}
	})

	authHeaderWithDirectKey := map[string]string{
		headers.Authorization: directKey,
	}

	authHeaderWithPolicyAppliedKey := map[string]string{
		headers.Authorization: policyAppliedKey,
	}

	t.Run("Depth limit exceeded", func(t *testing.T) {
		request := gql.Request{
			OperationName: "Hello",
			Variables:     nil,
			Query:         "query Hello { hello { numOfLetters } }",
		}

		if directSession.MaxQueryDepth != 1 || policyAppliedSession.MaxQueryDepth != 1 {
			t.Fatal("MaxQueryDepth couldn't be applied to key")
		}

		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
			{Headers: authHeaderWithPolicyAppliedKey, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Valid query should successfully work", func(t *testing.T) {
		request := gql.Request{
			OperationName: "Hello",
			Variables:     nil,
			Query:         "query Hello { hello { numOfLetters } }",
		}

		directSession.MaxQueryDepth = 2
		_ = GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

		_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
	})
}

const gqlIntrospectionQuery = `query IntrospectionQuery {
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
