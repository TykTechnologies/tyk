package gateway

import (
	"net/http"
	"testing"

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

	t.Run("Correct schema", func(t *testing.T) {
		spec.GraphQL.GraphQLAPI.Schema = "schema { query: Query } type Query { hello: String }"
		LoadAPI(spec)

		_, _ = g.Run(t, test.TestCase{Code: http.StatusOK})
	})
}
