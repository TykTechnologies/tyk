package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/v3/headers"
	"github.com/TykTechnologies/tyk/v3/test"
	"github.com/TykTechnologies/tyk/v3/user"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

func TestGraphQL_RestrictedTypes(t *testing.T) {
	g := StartTest()
	defer g.Close()

	api := BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.GraphQL.Enabled = true
	})[0]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"code"},
					},
				},
			},
		}
	})

	pID := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"name"},
					},
				},
			},
		}
	})

	_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	q1 := graphql.Request{
		Query: "query Query { countries { code } }",
	}

	q2 := graphql.Request{
		Query: "query Query { countries { name } }",
	}

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			headers.Authorization: directKey,
		}

		_, _ = g.Run(t, []test.TestCase{
			{Data: q1, Headers: authHeaderWithDirectKey,
				BodyMatch: `{"errors":\[{"message":"field: code is restricted on type: Country"}\]}`, Code: http.StatusBadRequest},
			{Data: q2, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Policy applied key", func(t *testing.T) {
		authHeaderWithPolicyAppliedKey := map[string]string{
			headers.Authorization: policyAppliedKey,
		}

		_, _ = g.Run(t, []test.TestCase{
			{Data: q2, Headers: authHeaderWithPolicyAppliedKey,
				BodyMatch: `{"errors":\[{"message":"field: name is restricted on type: Country"}\]}`, Code: http.StatusBadRequest},
			{Data: q1, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}
