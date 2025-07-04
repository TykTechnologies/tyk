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

			// Should retain original query params
			{Method: "POST", Path: "/xml?a=b", Data: getAction, BodyMatch: `"Url":"/get_action`},

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

			// Should retain original query params
			{Method: "POST", Path: "/virt?a=b", Data: getAction, BodyMatch: `"Url":"/get_action`},

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
		err := oasObj.ExtractTo(&oasAPIDef)
		assert.NoError(t, err)

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
