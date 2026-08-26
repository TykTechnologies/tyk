package gateway

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"

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

// TestGranularAccessMiddleware_RequireParameterAbsent covers the rule the
// feature exists for: an endpoint a caller may reach, but only without the
// parameters that turn it into someone else's lookup.
func TestGranularAccessMiddleware_RequireParameterAbsent(t *testing.T) {
	// An empty pattern places no constraint on the value, so reversing it
	// means "this name must not be supplied at all". This is the spelling the
	// documentation should lead with; ".*" with Reverse is equivalent.
	mustBeAbsent := apidef.StringRegexMap{Reverse: true}

	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = false
	})[0]

	_, key := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedURLs: []user.AccessSpec{{
					URL:     "/test/connections",
					Methods: []string{http.MethodGet},
					Conditions: []user.AccessCondition{{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"persnbr":  mustBeAbsent,
								"agreenbr": mustBeAbsent,
								"account":  mustBeAbsent,
							},
						},
					}},
				}},
			},
		}
	})

	headers := map[string]string{header.Authorization: key}

	for _, tc := range []struct {
		name string
		path string
		code int
	}{
		{name: "bare request is the caller's own connections", path: "/test/connections", code: http.StatusOK},
		{name: "an unrelated parameter is still fine", path: "/test/connections?page=2", code: http.StatusOK},
		{name: "persnbr looks up another person", path: "/test/connections?persnbr=123", code: http.StatusForbidden},
		{name: "agreenbr looks up another agreement", path: "/test/connections?agreenbr=99", code: http.StatusForbidden},
		{name: "account looks up another account", path: "/test/connections?account=7", code: http.StatusForbidden},
		{name: "an empty value is still a supplied parameter", path: "/test/connections?persnbr=", code: http.StatusForbidden},
		{name: "one forbidden parameter among allowed ones is enough", path: "/test/connections?page=2&persnbr=1", code: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = g.Run(t, test.TestCase{Path: tc.path, Method: http.MethodGet, Code: tc.code, Headers: headers})
		})
	}
}

// TestGranularAccessMiddleware_UnconditionalGrantWins pins down what happens
// when a key holds both an unconditional and a conditional entry for the same
// endpoint. allowed_urls is a list of grants, and grants are additive, so the
// unconditional one decides it: the conditional entry can only ever widen
// access, never narrow what another entry already allows.
//
// This matters when policies are combined: adding a policy to a key must not
// silently tighten an endpoint another policy already granted outright.
func TestGranularAccessMiddleware_UnconditionalGrantWins(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = false
	})[0]

	conditional := user.AccessSpec{
		URL:     "/test/orders",
		Methods: []string{http.MethodGet},
		Conditions: []user.AccessCondition{{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{"customer_id": {MatchPattern: "^123$"}},
			},
		}},
	}
	unconditional := user.AccessSpec{URL: "/test/orders", Methods: []string{http.MethodGet}}

	// Both orderings, because the middleware returns on the first entry that
	// matches and the order of allowed_urls must not change the outcome.
	for _, tc := range []struct {
		name  string
		specs []user.AccessSpec
	}{
		{name: "unconditional first", specs: []user.AccessSpec{unconditional, conditional}},
		{name: "conditional first", specs: []user.AccessSpec{conditional, unconditional}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, key := g.CreateSession(func(s *user.SessionState) {
				s.AccessRights = map[string]user.AccessDefinition{
					api.APIID: {APIID: api.APIID, APIName: api.Name, AllowedURLs: tc.specs},
				}
			})

			headers := map[string]string{header.Authorization: key}

			// The condition is not satisfied, but the unconditional grant is.
			_, _ = g.Run(t, test.TestCase{Path: "/test/orders?customer_id=999", Code: http.StatusOK, Headers: headers})
			// An endpoint neither entry names is still refused.
			_, _ = g.Run(t, test.TestCase{Path: "/test/invoices", Code: http.StatusForbidden, Headers: headers})
		})
	}
}

// TestGranularAccessMiddleware_StoredUncompilablePatternDenies covers a key
// whose condition cannot be compiled. The key API rejects these now
// (TestKeyHandler_RejectsInvalidAccessConditions), so the only way to hold one
// is to have stored it before that validation existed, or to have received it
// from an older control plane over MDCB. The session is therefore written
// straight to storage here, bypassing the API.
//
// The middleware has to deny such a request. Access conditions fail closed: a
// rule the Gateway cannot read must never be treated as satisfied.
func TestGranularAccessMiddleware_StoredUncompilablePatternDenies(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = false
	})[0]

	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{
		api.APIID: {
			APIID:   api.APIID,
			APIName: api.Name,
			AllowedURLs: []user.AccessSpec{{
				URL:     "/test/orders",
				Methods: []string{http.MethodGet},
				Conditions: []user.AccessCondition{{
					On: apidef.All,
					Options: apidef.RoutingTriggerOptions{
						QueryValMatches: map[string]apidef.StringRegexMap{"customer_id": {MatchPattern: "["}},
					},
				}},
			}},
		},
	}

	key := "stored-uncompilable-condition"
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(key, session, 60, false))

	_, _ = ts.Run(t, test.TestCase{
		Path:    "/test/orders?customer_id=123",
		Method:  http.MethodGet,
		Code:    http.StatusForbidden,
		Headers: map[string]string{header.Authorization: key},
	})
}

// TestGranularAccessMiddleware_ConditionsAreAuthAgnostic checks that a
// condition reaching the Gateway through a JWT-derived session behaves exactly
// as it does for an auth token.
//
// The middleware runs after authentication, against the normalised session, so
// this holds by construction for every authentication method Tyk supports.
// That is the argument for not testing each of them; it is also exactly the
// kind of argument that stops being true without anyone noticing, so the two
// ends of the range are pinned here.
func TestGranularAccessMiddleware_ConditionsAreAuthAgnostic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "conditions-auth-agnostic"

	allowedURLs := []user.AccessSpec{{
		URL:     "/connections$",
		Methods: []string{http.MethodGet},
		Conditions: []user.AccessCondition{{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{
					// Present and all digits, or the request is refused.
					"persnbr": {MatchPattern: "^[0-9]+$"},
				},
			},
		}},
	}}

	const jwtAPIID = "conditions-auth-agnostic-jwt"

	// Same conditions, same requests, two authentication methods. Both APIs
	// are loaded in one call: LoadAPI replaces the whole set, so loading them
	// separately would leave only the second.
	apis := ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = apiID
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/token"
		},
		func(spec *APISpec) {
			spec.APIID = jwtAPIID
			spec.UseKeylessAccess = false
			spec.EnableJWT = true
			spec.JWTSigningMethod = RSASign
			spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
			spec.JWTIdentityBaseField = "user_id"
			spec.JWTPolicyFieldName = "policy_id"
			spec.Proxy.ListenPath = "/jwt"
			spec.DisableRateLimit = true
			spec.DisableQuota = true
		},
	)
	authTokenAPI := apis[0]

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			authTokenAPI.APIID: {APIID: authTokenAPI.APIID, APIName: authTokenAPI.Name, AllowedURLs: allowedURLs},
		}
	})

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			jwtAPIID: {APIID: jwtAPIID, APIName: "conditions-auth-agnostic-jwt", AllowedURLs: allowedURLs},
		}
	})

	jwtToken := CreateJWKToken(func(token *jwt.Token) {
		token.Header["kid"] = "12345"
		token.Claims.(jwt.MapClaims)["user_id"] = "user"
		token.Claims.(jwt.MapClaims)["policy_id"] = policyID
		token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(72 * time.Hour).Unix()
	})

	for _, request := range []struct {
		name  string
		query string
		code  int
	}{
		{name: "valid person number", query: "?persnbr=123", code: http.StatusOK},
		{name: "person number is not digits", query: "?persnbr=abc", code: http.StatusForbidden},
		{name: "person number missing", query: "", code: http.StatusForbidden},
		{name: "a second value that does not match", query: "?persnbr=123&persnbr=evil", code: http.StatusForbidden},
	} {
		t.Run(request.name, func(t *testing.T) {
			_, _ = ts.Run(t, []test.TestCase{
				{
					Path:    "/token/connections" + request.query,
					Code:    request.code,
					Headers: map[string]string{header.Authorization: key},
				},
				{
					Path:    "/jwt/connections" + request.query,
					Code:    request.code,
					Headers: map[string]string{"authorization": jwtToken},
				},
			}...)
		})
	}
}
