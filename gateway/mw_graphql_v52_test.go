//go:build v52
// +build v52

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestGraphQLMiddleware_OpenTelemetry(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
	})[0]

	t.Run("fail input validation with otel tracing active", func(t *testing.T) {
		local := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = true
		})
		defer local.Close()
		testSpec := BuildAPI(func(spec *APISpec) {
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Schema = gqlCountriesSchema
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			spec.Proxy.TargetURL = testGraphQLProxyUpstream
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
		})[0]

		local.Gw.LoadAPI(testSpec)

		_, err := local.Run(
			t,
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlContinentQueryVariable,
					Variables: []byte(`{"code":null}`),
				},
				Code: 400,
			},
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlStateQueryVariable,
					Variables: []byte(`{"filter":{"code":{"eq":"filterString"}}}`),
				},
				Code: 400,
				BodyMatchFunc: func(i []byte) bool {
					return strings.Contains(string(i), `Validation for variable \"filter\" failed`)
				},
			})
		assert.NoError(t, err)
	})
}
