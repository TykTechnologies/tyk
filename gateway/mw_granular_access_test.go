package gateway

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGranularAccessMiddleware_ProcessRequest(t *testing.T) {
	g := StartTest(func(c *config.Config) {
		c.HttpServerOptions.EnablePathPrefixMatching = true
	})
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = false
	})[0]

	allowedURLs := []user.AccessSpec{
		{
			URL:     "^/valid_path",
			Methods: []string{"GET"},
		},
		{
			URL:     "^/test/try_valid_path",
			Methods: []string{"GET"},
		},
	}

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:       api.APIID,
				APIName:     api.Name,
				AllowedURLs: allowedURLs,
			},
		}
	})

	pID := g.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:       api.APIID,
				APIName:     api.Name,
				AllowedURLs: allowedURLs,
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

		t.Run("should return 200 OK on regex matching listen path", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/try_valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

		t.Run("should return 200 OK on allowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on allowed path with disallowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/valid_path",
					Method:  http.MethodPost,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on disallowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/invalid_path",
					Method:  http.MethodGet,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

	})

	t.Run("Policy applied key", func(t *testing.T) {
		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		t.Run("should return 200 OK on regex matching listen path", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/try_valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})

		t.Run("should return 200 OK on allowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on allowed path with disallowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/valid_path",
					Method:  http.MethodPost,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on disallowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/test/invalid_path",
					Method:  http.MethodGet,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})
	})
}

func TestGranularAccessMiddleware_Conditions(t *testing.T) {
	queryCondition := func(param, pattern string) user.AccessCondition {
		return user.AccessCondition{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{
					param: {MatchPattern: pattern},
				},
			},
		}
	}

	testCases := []struct {
		name       string
		conditions []user.AccessCondition
		path       string
		method     string
		headers    map[string]string
		body       string
		code       int
	}{
		{
			name:   "no conditions still matches on url and method alone",
			path:   "/test/orders",
			method: http.MethodGet,
			code:   http.StatusOK,
		},
		{
			name:       "query value matches",
			conditions: []user.AccessCondition{queryCondition("customer_id", "^123$")},
			path:       "/test/orders?customer_id=123",
			method:     http.MethodGet,
			code:       http.StatusOK,
		},
		{
			name:       "query value does not match",
			conditions: []user.AccessCondition{queryCondition("customer_id", "^123$")},
			path:       "/test/orders?customer_id=456",
			method:     http.MethodGet,
			code:       http.StatusForbidden,
		},
		{
			name:       "query param absent",
			conditions: []user.AccessCondition{queryCondition("customer_id", "^123$")},
			path:       "/test/orders",
			method:     http.MethodGet,
			code:       http.StatusForbidden,
		},
		{
			name: "reversed query match denies on match",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						"role": {MatchPattern: "^admin$", Reverse: true},
					},
				},
			}},
			path:   "/test/orders?role=admin",
			method: http.MethodGet,
			code:   http.StatusForbidden,
		},
		{
			name: "header matches",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:    "/test/orders",
			method:  http.MethodGet,
			headers: map[string]string{"X-Tenant": "acme"},
			code:    http.StatusOK,
		},
		{
			name: "header does not match",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:    "/test/orders",
			method:  http.MethodGet,
			headers: map[string]string{"X-Tenant": "globex"},
			code:    http.StatusForbidden,
		},
		{
			name: "payload matches",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					PayloadMatches: apidef.StringRegexMap{MatchPattern: `"tenant":\s*"acme"`},
				},
			}},
			path:   "/test/orders",
			method: http.MethodGet,
			body:   `{"tenant": "acme"}`,
			code:   http.StatusOK,
		},
		{
			name: "payload does not match",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					PayloadMatches: apidef.StringRegexMap{MatchPattern: `"tenant":\s*"acme"`},
				},
			}},
			path:   "/test/orders",
			method: http.MethodGet,
			body:   `{"tenant": "globex"}`,
			code:   http.StatusForbidden,
		},
		{
			name: "on all requires every option to match",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						"customer_id": {MatchPattern: "^123$"},
					},
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:   "/test/orders?customer_id=123",
			method: http.MethodGet,
			code:   http.StatusForbidden,
		},
		{
			name: "on all with every option matching",
			conditions: []user.AccessCondition{{
				On: apidef.All,
				Options: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						"customer_id": {MatchPattern: "^123$"},
					},
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:    "/test/orders?customer_id=123",
			method:  http.MethodGet,
			headers: map[string]string{"X-Tenant": "acme"},
			code:    http.StatusOK,
		},
		{
			name: "on any needs only one option to match",
			conditions: []user.AccessCondition{{
				On: apidef.Any,
				Options: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						"customer_id": {MatchPattern: "^123$"},
					},
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:   "/test/orders?customer_id=123",
			method: http.MethodGet,
			code:   http.StatusOK,
		},
		{
			name: "on any with no option matching",
			conditions: []user.AccessCondition{{
				On: apidef.Any,
				Options: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						"customer_id": {MatchPattern: "^123$"},
					},
					HeaderMatches: map[string]apidef.StringRegexMap{
						"X-Tenant": {MatchPattern: "^acme$"},
					},
				},
			}},
			path:   "/test/orders?customer_id=456",
			method: http.MethodGet,
			code:   http.StatusForbidden,
		},
		{
			name: "multiple conditions combine with and",
			conditions: []user.AccessCondition{
				queryCondition("customer_id", "^123$"),
				queryCondition("region", "^eu$"),
			},
			path:   "/test/orders?customer_id=123&region=eu",
			method: http.MethodGet,
			code:   http.StatusOK,
		},
		{
			name: "multiple conditions with one unsatisfied",
			conditions: []user.AccessCondition{
				queryCondition("customer_id", "^123$"),
				queryCondition("region", "^eu$"),
			},
			path:   "/test/orders?customer_id=123&region=us",
			method: http.MethodGet,
			code:   http.StatusForbidden,
		},
		{
			name:       "uncompilable pattern denies access",
			conditions: []user.AccessCondition{queryCondition("customer_id", "[")},
			path:       "/test/orders?customer_id=123",
			method:     http.MethodGet,
			code:       http.StatusForbidden,
		},
	}

	// The two path matching modes reach the allowed URL loop by different
	// branches, so both have to honour conditions.
	for _, prefixMatching := range []bool{false, true} {
		t.Run(fmt.Sprintf("EnablePathPrefixMatching=%v", prefixMatching), func(t *testing.T) {
			g := StartTest(func(c *config.Config) {
				c.HttpServerOptions.EnablePathPrefixMatching = prefixMatching
			})
			defer g.Close()

			api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/test"
				spec.UseKeylessAccess = false
			})[0]

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					_, key := g.CreateSession(func(s *user.SessionState) {
						s.AccessRights = map[string]user.AccessDefinition{
							api.APIID: {
								APIID:   api.APIID,
								APIName: api.Name,
								AllowedURLs: []user.AccessSpec{{
									URL:        "/test/orders",
									Methods:    []string{http.MethodGet},
									Conditions: tc.conditions,
								}},
							},
						}
					})

					headers := map[string]string{header.Authorization: key}
					for k, v := range tc.headers {
						headers[k] = v
					}

					_, _ = g.Run(t, test.TestCase{
						Path:    tc.path,
						Method:  tc.method,
						Data:    tc.body,
						Code:    tc.code,
						Headers: headers,
					})
				})
			}
		})
	}
}
