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

	t.Run("Empty request should return error", func(t *testing.T) {
		emptyRequest := ``

		_, _ = g.Run(t, test.TestCase{Data: emptyRequest, BodyMatch: gql.ErrEmptyRequest.Error(), Code: http.StatusBadRequest})
	})

	t.Run("Non-empty request should be successfully unmarshalled", func(t *testing.T) {
		nonEmptyRequest := `{"operation_name": "Hello", "variables": "", "query": "query Hello { hello }"}`

		_, _ = g.Run(t, test.TestCase{Data: nonEmptyRequest, BodyMatch: "hello", Code: http.StatusOK})
	})
}
