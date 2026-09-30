package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGraphQL_RestrictedTypes(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	pID := g.CreatePolicy(func(p *user.Policy) {
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

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			header.Authorization: directKey,
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		unrestrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithDirectKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: code is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: unrestrictedQuery, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Policy applied key", func(t *testing.T) {
		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		unrestrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithPolicyAppliedKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: name is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: unrestrictedQuery, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}

func TestGraphQL_AllowedTypes(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.GraphQL.Enabled = true
	})[0]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"code"},
					},
					{
						Name:   "Query",
						Fields: []string{"countries"},
					},
				},
			},
		}
	})

	pID := g.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"name"},
					},
					{
						Name:   "Query",
						Fields: []string{"countries"},
					},
				},
			},
		}
	})

	_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			header.Authorization: directKey,
		}

		allowedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithDirectKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: name is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: allowedQuery, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Policy applied key", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5220

		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		allowedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithPolicyAppliedKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: code is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: allowedQuery, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}

func TestGraphQL_AllowedTypes_Override_RestrictedTypes(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.GraphQL.Enabled = true
	})[0]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"code"},
					},
					{
						Name:   "Query",
						Fields: []string{"countries"},
					},
				},
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"code"},
					},
				},
			},
		}
	})

	pID := g.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"name"},
					},
					{
						Name:   "Query",
						Fields: []string{"countries"},
					},
				},
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

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			header.Authorization: directKey,
		}

		allowedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithDirectKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: name is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: allowedQuery, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Policy applied key", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5220

		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		allowedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithPolicyAppliedKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: code is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: allowedQuery, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}

func TestGraphQL_DisableIntrospection(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	disabledIntrospectionBody := `{
    "error": "introspection is disabled"
}`

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.GraphQL.Enabled = true
	})[0]

	introspectionQuery := graphql.Request{
		Query: "query Query { __schema { types { name } } }",
	}

	t.Run("Disable Introspection with direct key", func(t *testing.T) {
		_, disableIntrospectionKey := g.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:                api.APIID,
					APIName:              api.Name,
					DisableIntrospection: true,
				},
			}
		})

		authHeaderWithDirectKey := map[string]string{
			header.Authorization: disableIntrospectionKey,
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    introspectionQuery,
				Headers: authHeaderWithDirectKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), disabledIntrospectionBody)
				},
				Code: http.StatusForbidden,
			},
		}...)
	})

	t.Run("Enable Introspection with direct key", func(t *testing.T) {
		_, enabledIntrospectionKey := g.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
				},
			}
		})

		authHeaderWithDirectKey := map[string]string{
			header.Authorization: enabledIntrospectionKey,
		}

		_, _ = g.Run(t, []test.TestCase{
			{Data: introspectionQuery, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Disable introspection with policy applied key", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5220

		pID := g.CreatePolicy(func(p *user.Policy) {
			p.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:                api.APIID,
					APIName:              api.Name,
					DisableIntrospection: true,
				},
			}
		})

		_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
		})

		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    introspectionQuery,
				Headers: authHeaderWithPolicyAppliedKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), disabledIntrospectionBody)
				},
				Code: http.StatusForbidden,
			},
		}...)
	})

	t.Run("Enable introspection with policy applied key", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5220

		pID := g.CreatePolicy(func(p *user.Policy) {
			p.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
				},
			}
		})

		_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
		})

		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}
		_, _ = g.Run(t, []test.TestCase{
			{Data: introspectionQuery, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}

func TestGraphQL_GranularAccess_ErrorOverride_TT_18106(t *testing.T) {
	g := StartTest(nil)
	t.Cleanup(g.Close)

	apis := g.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api1"
			spec.UseKeylessAccess = false
			spec.GraphQL.Enabled = true
			spec.GraphQL.Schema = `
            	type Query { accounts: [Account] }
            	type Account { id: ID! name: String secretKey: String }
        	`
			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"400": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: http.StatusForbidden,
							Body:       `{"errors":[{"message":"Access denied"}]}`,
						},
					},
				},
			}
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api2"
			spec.UseKeylessAccess = false
			spec.GraphQL.Enabled = true
			spec.GraphQL.Schema = `
            	type Query { accounts: [Account] }
            	type Account { id: ID! name: String secretKey: String }
        	`
		},
	)

	api1 := apis[0]
	api2 := apis[1]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api1.APIID: {
				APIID:   api1.APIID,
				APIName: api1.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Account",
						Fields: []string{"secretKey"},
					},
				},
			},
			api2.APIID: {
				APIID:   api1.APIID,
				APIName: api1.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Account",
						Fields: []string{"secretKey"},
					},
				},
			},
		}
	})

	t.Run("fetching secured field makes server to respond with mapped error", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{
			Path: "/api1",
			Data: graphql.Request{
				Query: "query { accounts { id name secretKey } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code: http.StatusForbidden,
			BodyMatchFunc: func(bytes []byte) bool {
				return string(bytes) == `{"errors":[{"message":"Access denied"}]}`
			},
		})
	})

	t.Run("fetching allowed fields makes server respond 200 Ok", func(t *testing.T) {
		// Proper request
		res, _ := g.Run(t, test.TestCase{
			Path: "/api1",
			Data: graphql.Request{
				Query: "query { accounts { id name } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code: http.StatusOK,
		})

		_ = res
	})

	// old behavior when error override mechanic is not enabled
	t.Run("fetching secured field makes server to respond original 400 error", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{
			Path: "/api2",
			Data: graphql.Request{
				Query: "query { accounts { id name secretKey } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code:         http.StatusBadRequest,
			HeadersMatch: map[string]string{},
			BodyMatchFunc: func(bytes []byte) bool {
				t.Logf("body=%s", string(bytes))
				return assert.Equal(t, `{"errors":[{"message":"field: secretKey is restricted on type: Account"}]}`, string(bytes))
			},
		})
	})
}
