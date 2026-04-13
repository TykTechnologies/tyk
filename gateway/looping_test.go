//go:build !race || unstable
// +build !race unstable

// Looping by itself has race nature
package gateway

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestLooping(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	postAction := `<operation action="https://example.com/post_action">data</operation>`
	getAction := `<operation action="https://example.com/get_action">data</operation>`

	t.Run("Using advanced URL rewrite", func(t *testing.T) {
		// We defined internnal advanced rewrite based on body data
		// which rewrites to internal paths (marked as blacklist so they protected from outside world)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "internal": [{
                        "path": "/get_action",
                        "method": "GET"
                    },{
                        "path": "/post_action",
                        "method": "POST"
                    }],
                    "white_list": [{
                        "path": "/xml",
                        "method_actions": {"POST": {"action": "no_action"}}
                    }],
                    "url_rewrites": [{
                        "path": "/xml",
                        "method": "POST",
                        "match_pattern": "/xml(.*)",
                        "rewrite_to": "/xml$1",
                        "triggers": [
                          {
                            "on": "all",
                            "options": {
                              "payload_matches": {
                                "match_rx": "post_action"
                              }
                            },
                            "rewrite_to": "tyk://self/post_action"
                          },
                          {
                            "on": "all",
                            "options": {
                              "payload_matches": {
                                "match_rx": "get_action"
                              }
                            },
                            "rewrite_to": "tyk://self/get_action?method=GET"
                          }
                        ]
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/xml", Data: postAction, BodyMatch: `"Url":"/post_action`},

			// Should use rewritten path query params, not original request query params
			{Method: "POST", Path: "/xml?a=b", Data: getAction, BodyMatch: `"Url":"/get_action"`, BodyNotMatch: `a=b`},

			// Should rewrite http method, if loop rewrite param passed
			{Method: "POST", Path: "/xml", Data: getAction, BodyMatch: `"Method":"GET"`},

			// Internal endpoint can be accessed only via looping
			{Method: "GET", Path: "/get_action", Code: 403},

			{Method: "POST", Path: "/get_action", Code: 403},
		}...)
	})

	t.Run("Test multiple url rewrites", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
			"internal": [{
                        	"path": "/hidden_path",
                        	"method": "GET"
                    	}],
			"url_rewrites": [{
                        	"path": "/test",
                        	"match_pattern": "/test",
                        	"method": "GET",
				"rewrite_to":"tyk://self/hidden_path_1"
                    	},{
                        	"path": "/hidden_path_1",
                        	"match_pattern": "/hidden_path_1",
                        	"method": "GET",
				"rewrite_to":"tyk://self/hidden_path_2"
                    	},{
                        	"path": "/hidden_path_2",
                        	"match_pattern": "/hidden_path_2",
                        	"method": "GET",
				"rewrite_to":"/upstream"
		    	}]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
		})

		//addHeaders := map[string]string{"X-Test": "test", "X-Internal": "test"}

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/test", BodyMatch: `"Url":"/upstream"`},
		}...)
	})

	t.Run("Loop to another API", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "testid"
			spec.Name = "hidden api"
			spec.Proxy.ListenPath = "/somesecret"
			spec.Internal = true
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "global_headers": {
                    "X-Name":"internal"
                }
            }`), &version)
			spec.VersionData.Versions["v1"] = version
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test"

			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/by_name",
                        "match_pattern": "/by_name(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://hidden api/get"
                    },{
                        "path": "/by_id",
                        "match_pattern": "/by_id(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://testid/get"
                    },{
                        "path": "/wrong",
                        "match_pattern": "/wrong(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://wrong/get"
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version
		})

		ts.Run(t, []test.TestCase{
			{Path: "/somesecret", Code: 404},
			{Path: "/test/by_name", Code: 200, BodyMatch: `"X-Name":"internal"`},
			{Path: "/test/by_id", Code: 200, BodyMatch: `"X-Name":"internal"`},
			{Path: "/test/wrong", Code: 500},
		}...)
	})

	t.Run("VirtualEndpoint or plugins", func(t *testing.T) {
		test.Flaky(t) // TT-10511

		ts.testPrepareVirtualEndpoint(`
            function testVirtData(request, session, config) {
                var loopLocation = "/default"

                if (request.Body.match("post_action")) {
                    loopLocation = "tyk://self/post_action"
                } else if (request.Body.match("get_action")) {
                    loopLocation = "tyk://self/get_action?method=GET"
                }

                var resp = {
                    Headers: {
                        "Location": loopLocation,
                    },
                    Code: 302
                }
                return TykJsResponse(resp, session.meta_data)
            }
        `, "POST", "/virt", true, true, false, false)

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/virt", Data: postAction, BodyMatch: `"Url":"/post_action`},

			// Should use rewritten path query params, not original request query params
			{Method: "POST", Path: "/virt?a=b", Data: getAction, BodyMatch: `"Url":"/get_action"`, BodyNotMatch: `a=b`},

			// Should rewrite http method, if loop rewrite param passed
			{Method: "POST", Path: "/virt", Data: getAction, BodyMatch: `"Method":"GET"`},
		}...)
	})

	t.Run("Loop limit", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/recursion",
                        "match_pattern": "/recursion(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://self/recursion?loop_limit=2"
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/recursion", Code: 500, BodyMatch: "Loop level too deep. Found more than 2 loops in single request"},
		}...)
	})

	t.Run("Quota and rate limit calculation", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/recursion",
                        "match_pattern": "/recursion(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://self/recursion?loop_limit=2"
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = false
		})

		keyID := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.QuotaMax = 2
		})

		authHeaders := map[string]string{"authorization": keyID}

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/recursion", Headers: authHeaders, BodyNotMatch: "Quota exceeded"},
		}...)
	})

	t.Run("Rewritten query params preserved, original dropped", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			err := json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "internal": [
                        {"path": "/target", "method": "GET"},
                        {"path": "/target", "method": "POST"}
                    ],
                    "url_rewrites": [
                        {
                            "path": "/rewrite_with_param",
                            "match_pattern": "/rewrite_with_param",
                            "method": "GET",
                            "rewrite_to": "tyk://self/target?foo=bar"
                        },
                        {
                            "path": "/rewrite_method_only",
                            "match_pattern": "/rewrite_method_only",
                            "method": "GET",
                            "rewrite_to": "tyk://self/target?method=POST"
                        },
                        {
                            "path": "/rewrite_param_and_method",
                            "match_pattern": "/rewrite_param_and_method",
                            "method": "GET",
                            "rewrite_to": "tyk://self/target?foo=bar&method=POST"
                        },
                        {
                            "path": "/rewrite_no_params",
                            "match_pattern": "/rewrite_no_params",
                            "method": "GET",
                            "rewrite_to": "tyk://self/target"
                        }
                    ]
                }
            }`), &version)
			assert.NoError(t, err)

			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
		})

		// tyk://api/path?foo=bar, foo=bar passed to target
		t.Run("rewrite with user query param", func(t *testing.T) {
			ts.Run(t, []test.TestCase{
				{Method: "GET", Path: "/rewrite_with_param", BodyMatch: `foo=bar`},
			}...)
		})

		// tyk://api/path?method=POST, method consumed and dropped
		t.Run("rewrite with method control param only", func(t *testing.T) {
			ts.Run(t, []test.TestCase{
				{Method: "GET", Path: "/rewrite_method_only",
					BodyMatch:    `"Method":"POST"`,
					BodyNotMatch: `method=POST`},
			}...)
		})

		// tyk://api/path?foo=bar&method=POST, foo=bar preserved, method consumed + dropped
		t.Run("rewrite with user and control params", func(t *testing.T) {
			ts.Run(t, []test.TestCase{
				{Method: "GET", Path: "/rewrite_param_and_method",
					BodyMatch:    `foo=bar`,
					BodyNotMatch: `method=POST`},
				{Method: "GET", Path: "/rewrite_param_and_method",
					BodyMatch: `"Method":"POST"`},
			}...)
		})

		// tyk://api/path?a=b, a=b dropped (must be explicit in rewrite)
		t.Run("original query params dropped", func(t *testing.T) {
			ts.Run(t, []test.TestCase{
				{Method: "GET", Path: "/rewrite_no_params?a=b",
					BodyNotMatch: `a=b`},
				{Method: "GET", Path: "/rewrite_with_param?a=b",
					BodyMatch:    `foo=bar`,
					BodyNotMatch: `a=b`},
			}...)
		})
	})

	t.Run("loop external native def to internal OAS", func(t *testing.T) {
		// Create internal OAS API
		tykExtension := oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "internal",
				ID:   "internal-api",
				State: oas.State{
					Active:   false,
					Internal: true,
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/internal/",
					Strip: false,
				},
			},
		}

		oasAPI := openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: openapi3.NewPaths(),
		}

		oasObj := oas.OAS{T: oasAPI}
		oasObj.SetTykExtension(&tykExtension)

		oasAPIDef := apidef.APIDefinition{}
		oasObj.ExtractTo(&oasAPIDef)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "external-api"
			spec.Name = "external"
			spec.Proxy.ListenPath = "/external/"
			spec.Proxy.TargetURL = "tyk://internal/"
		}, func(spec *APISpec) {
			spec.APIDefinition = &oasAPIDef
			spec.OAS = oasObj
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/external/", Code: 200},
		}...)
	})
}

func TestLooping_AnotherAPIWithAuthTokens(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Looping to another api with auth tokens
	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIDefinition.APIID = "apia"
		spec.APIDefinition.Name = "ApiA"
		spec.APIDefinition.Proxy.ListenPath = "/apia"
		spec.APIDefinition.UseKeylessAccess = false
		spec.APIDefinition.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {
				AuthHeaderName: "Authorization",
			},
		}

		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/",
				Method:       http.MethodGet,
				MatchPattern: ".*",
				RewriteTo:    "tyk://apib",
			}}
		})
	}, func(spec *APISpec) {
		spec.APIDefinition.APIID = "apib"
		spec.APIDefinition.Name = "ApiB"
		spec.APIDefinition.Proxy.ListenPath = "/apib"
		spec.APIDefinition.UseKeylessAccess = false
		spec.APIDefinition.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {
				AuthHeaderName: "X-Api-Key",
			},
		}
	})
	specApiA := specs[0]
	specApiB := specs[1]

	_, authKeyForApiA := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			specApiA.APIDefinition.APIID: {
				APIName:        specApiA.APIDefinition.Name,
				APIID:          specApiA.APIDefinition.APIID,
				Versions:       []string{"default"},
				AllowanceScope: specApiA.APIDefinition.APIID,
			},
		}
		s.OrgID = specApiA.APIDefinition.OrgID
	})

	_, authKeyForApiB := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			specApiB.APIDefinition.APIID: {
				APIName:        specApiB.APIDefinition.Name,
				APIID:          specApiB.APIDefinition.APIID,
				Versions:       []string{"default"},
				AllowanceScope: specApiB.APIDefinition.APIID,
			},
		}
		s.OrgID = specApiB.APIDefinition.OrgID
	})

	headersWithApiBToken := map[string]string{
		"Authorization": authKeyForApiA,
		"X-Api-Key":     authKeyForApiB,
	}
	headersWithoutApiBToken := map[string]string{
		"Authorization": authKeyForApiA,
		"X-Api-Key":     "some-string",
	}
	headersWithOnlyApiAToken := map[string]string{
		"Authorization": authKeyForApiA,
	}
	_, _ = ts.Run(t, []test.TestCase{
		{
			Headers: headersWithApiBToken,
			Path:    "/apia",
			Code:    http.StatusOK,
		},
		{
			Headers:   headersWithoutApiBToken,
			Path:      "/apia",
			Code:      http.StatusForbidden,
			BodyMatch: "Access to this API has been disallowed",
		},
		{
			Headers:   headersWithOnlyApiAToken,
			Path:      "/apia",
			Code:      http.StatusUnauthorized,
			BodyMatch: "Authorization field missing",
		},
	}...)
}

func TestLoopingControlParams(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("method overrides HTTP method", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			assert.NoError(t, json.Unmarshal([]byte(`{
				"use_extended_paths": true,
				"extended_paths": {
					"internal": [
						{"path": "/target", "method": "GET"},
						{"path": "/target", "method": "POST"},
						{"path": "/target", "method": "PUT"},
						{"path": "/target", "method": "DELETE"}
					],
					"url_rewrites": [
						{
							"path": "/to_post",
							"match_pattern": "/to_post",
							"method": "GET",
							"rewrite_to": "tyk://self/target?method=POST"
						},
						{
							"path": "/to_put",
							"match_pattern": "/to_put",
							"method": "GET",
							"rewrite_to": "tyk://self/target?method=PUT"
						},
						{
							"path": "/to_delete",
							"match_pattern": "/to_delete",
							"method": "GET",
							"rewrite_to": "tyk://self/target?method=DELETE"
						},
						{
							"path": "/no_method",
							"match_pattern": "/no_method",
							"method": "GET",
							"rewrite_to": "tyk://self/target"
						}
					]
				}
			}`), &version))
			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
		})

		// GET overridden to POST
		t.Run("GET to POST", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/to_post",
				BodyMatch: `"Method":"POST"`,
			})
		})

		// GET overridden to PUT
		t.Run("GET to PUT", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/to_put",
				BodyMatch: `"Method":"PUT"`,
			})
		})

		// GET overridden to DELETE
		t.Run("GET to DELETE", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/to_delete",
				BodyMatch: `"Method":"DELETE"`,
			})
		})

		// No method param: original method preserved
		t.Run("no override keeps original method", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/no_method",
				BodyMatch: `"Method":"GET"`,
			})
		})

		// method param is stripped from query string reaching target
		t.Run("method param stripped from target query", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/to_post",
				BodyNotMatch: `method=POST`,
			})
		})
	})

	t.Run("loop_limit controls max recursion depth", func(t *testing.T) {
		// loop_limit=2: recursion should fail after 2 loops
		t.Run("exceeds limit", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/recurse",
							"match_pattern": "/recurse(.*)",
							"method": "GET",
							"rewrite_to": "tyk://self/recurse?loop_limit=2"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/recurse",
				Code:      500,
				BodyMatch: "Loop level too deep. Found more than 2 loops in single request",
			})
		})

		// loop_limit=3: same recursion fails after 3 loops
		t.Run("exceeds higher limit", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/recurse",
							"match_pattern": "/recurse(.*)",
							"method": "GET",
							"rewrite_to": "tyk://self/recurse?loop_limit=3"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/recurse",
				Code:      500,
				BodyMatch: "Found more than 3 loops",
			})
		})

		// No loop_limit: defaults to 5 (defaultLoopLevelLimit)
		t.Run("default limit is 5", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/recurse",
							"match_pattern": "/recurse(.*)",
							"method": "GET",
							"rewrite_to": "tyk://self/recurse"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/recurse",
				Code:      500,
				BodyMatch: "Found more than 5 loops",
			})
		})

		// Non-recursive loop within limit succeeds
		t.Run("single loop within limit succeeds", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/entry",
							"match_pattern": "/entry",
							"method": "GET",
							"rewrite_to": "tyk://self/final?loop_limit=2"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/entry",
				Code:      200,
				BodyMatch: `"Url":"/final"`,
			})
		})

		// loop_limit param is stripped from query string reaching target
		t.Run("loop_limit stripped from target query", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/entry",
				BodyNotMatch: `loop_limit`,
			})
		})
	})

	t.Run("check_limits controls rate limiting in loops", func(t *testing.T) {
		// Self-loop without check_limits: quota is NOT enforced (default for self-loops)
		t.Run("self loop skips quota by default", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/entry",
							"match_pattern": "/entry",
							"method": "GET",
							"rewrite_to": "tyk://self/dest"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
				spec.UseKeylessAccess = false
			})

			// QuotaMax=1: only 1 request allowed, but the looped leg should not consume quota
			keyID := CreateSession(ts.Gw, func(s *user.SessionState) {
				s.QuotaMax = 1
				s.QuotaRemaining = 1
			})
			authHeaders := map[string]string{"authorization": keyID}

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/entry", Headers: authHeaders,
				Code:         200,
				BodyNotMatch: "Quota exceeded",
			})
		})

		// Self-loop with check_limits=true: quota IS enforced on looped request
		t.Run("self loop enforces quota with check_limits=true", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/entry",
							"match_pattern": "/entry",
							"method": "GET",
							"rewrite_to": "tyk://self/dest?check_limits=true"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
				spec.UseKeylessAccess = false
			})

			// QuotaMax=1: first leg consumes quota, looped leg hits "Quota exceeded"
			keyID := CreateSession(ts.Gw, func(s *user.SessionState) {
				s.QuotaMax = 1
				s.QuotaRemaining = 1
			})
			authHeaders := map[string]string{"authorization": keyID}

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/entry", Headers: authHeaders,
				Code:      http.StatusForbidden,
				BodyMatch: "Quota exceeded",
			})
		})

		// check_limits param is stripped from query string reaching target
		t.Run("check_limits stripped from target query", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				version := spec.VersionData.Versions["v1"]
				assert.NoError(t, json.Unmarshal([]byte(`{
					"use_extended_paths": true,
					"extended_paths": {
						"url_rewrites": [{
							"path": "/entry",
							"match_pattern": "/entry",
							"method": "GET",
							"rewrite_to": "tyk://self/dest?check_limits=true"
						}]
					}
				}`), &version))
				spec.VersionData.Versions["v1"] = version
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/entry",
				BodyNotMatch: `check_limits`,
			})
		})
	})

	t.Run("all control params combined", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			assert.NoError(t, json.Unmarshal([]byte(`{
				"use_extended_paths": true,
				"extended_paths": {
					"internal": [
						{"path": "/target", "method": "POST"}
					],
					"url_rewrites": [{
						"path": "/all_params",
						"match_pattern": "/all_params",
						"method": "GET",
						"rewrite_to": "tyk://self/target?method=POST&loop_limit=3&check_limits=true&user_param=hello"
					}]
				}
			}`), &version))
			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = false
		})

		keyID := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.QuotaMax = 10
			s.QuotaRemaining = 10
		})
		authHeaders := map[string]string{"authorization": keyID}

		// method overridden to POST
		t.Run("method is POST", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/all_params", Headers: authHeaders,
				BodyMatch: `"Method":"POST"`,
			})
		})

		// user_param preserved, all control params stripped
		t.Run("user param preserved, control params stripped", func(t *testing.T) {
			ts.Run(t, test.TestCase{
				Method: "GET", Path: "/all_params", Headers: authHeaders,
				BodyMatch:    `user_param=hello`,
				BodyNotMatch: `loop_limit`,
			})
		})
	})
}

func TestConcurrencyReloads(t *testing.T) {
	test.Racy(t) // TT-10510

	var wg sync.WaitGroup

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			ts.Run(t, test.TestCase{Path: "/sample", Code: 200})
			wg.Done()
		}()
	}

	for j := 0; j < 5; j++ {
		ts.Gw.BuildAndLoadAPI()
	}

	wg.Wait()
}
