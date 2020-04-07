package gateway

import (
	"net/http"
	"testing"

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

	spec.GraphQL.GraphQLAPI.Schema = "schema { query: Query } type Query { hello: String }"
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

	t.Run("Valid query should successfully work", func(t *testing.T) {
		request := gql.Request{
			OperationName: "Hello",
			Variables:     nil,
			Query:         "query Hello { hello }",
		}

		_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: "hello", Code: http.StatusOK})
	})
}
