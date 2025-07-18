package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	texttemplate "text/template"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestURLRewrites(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Extended Paths with url_rewrites", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
						{
                            "path": "/rewrite1",
                            "method": "GET",
                            "match_pattern": "/rewrite1",
                            "rewrite_to": "",
                            "triggers": [
                                {
                                    "on": "all",
                                    "options": {
                                        "header_matches": {},
                                        "query_val_matches": {
                                            "show_env": {
                                                "match_rx": "1"
                                            }
                                        },
                                        "path_part_matches": {},
                                        "session_meta_matches": {},
                                        "payload_matches": {
                                            "match_rx": ""
                                        }
                                    },
                                    "rewrite_to": "/get?show_env=2"
                                }
                            ],
                            "MatchRegexp": null
                        },
                        {
                            "path": "/rewrite",
                            "method": "GET",
                            "match_pattern": "/rewrite",
                            "rewrite_to": "/get?just_rewrite",
                            "triggers": [],
                            "MatchRegexp": null
						}
				]`), &v.ExtendedPaths.URLRewrite)
			})
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/rewrite1?show_env=1", Code: http.StatusOK, BodyMatch: `"URI":"/get\?show_env=2"`},
			{Path: "/rewrite", Code: http.StatusOK, BodyMatch: `"URI":"/get\?just_rewrite"`},
		}...)
	})
}

func TestWhitelist(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/reply/{id}",
						"method_actions": {
							"GET": {"action": "reply", "code": 200, "data": "flump"}
						}
					},
					{
						"path": "/get",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.WhiteList)
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should mock path
			{Path: "/reply/", Code: http.StatusForbidden},
			{Path: "/reply/123", Code: http.StatusOK, BodyMatch: "flump"},
			// Should get original upstream response
			{Path: "/get", Code: http.StatusOK, BodyMatch: `"Url":"/get"`},
			// Reject not whitelisted (but know by upstream) path
			{Method: "POST", Path: "/post", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/simple", "pathWithoutSlash", "/regex/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should mock path
			{Path: "/simple", Code: http.StatusOK},
			{Path: "/pathWithoutSlash", Code: http.StatusOK},
			{Path: "/regex/123/test", Code: http.StatusOK},
			{Path: "/regex/123/differ", Code: http.StatusForbidden},
			{Path: "/", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Test #1944", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/foo/{fooId}$", "/foo/{fooId}/bar/{barId}$", "/baz/{bazId}"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusForbidden},
			{Path: "/foo/", Code: http.StatusForbidden},
			{Path: "/foo/1", Code: http.StatusOK},
			{Path: "/foo/1/bar", Code: http.StatusForbidden},
			{Path: "/foo/1/bar/", Code: http.StatusForbidden},
			{Path: "/foo/1/bar/1", Code: http.StatusOK},
			{Path: "/", Code: http.StatusForbidden},
			{Path: "/baz", Code: http.StatusForbidden},
			{Path: "/baz/", Code: http.StatusForbidden},
			{Path: "/baz/1", Code: http.StatusOK},
			{Path: "/baz/1/", Code: http.StatusOK},
			{Path: "/baz/1/bazz", Code: http.StatusOK},
		}...)
	})

	t.Run("Case Sensitivity", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/Foo", "/bar"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusForbidden},
			{Path: "/Foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusOK},
			{Path: "/Bar", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Listen path matches", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/fruits/fruit"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/fruits/"
		}, func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/vegetable$"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/vegetables/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/fruits/fruit", Code: http.StatusOK},
			{Path: "/fruits/count", Code: http.StatusForbidden},

			{Path: "/vegetables/vegetable", Code: http.StatusOK},
			{Path: "/vegetables/count", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Disabled", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths.WhiteList = []apidef.EndPointMeta{
					{Disabled: false, Path: "/foo"},
					{Disabled: true, Path: "/bar"},
				}
			})

			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusForbidden},
		}...)
	})
}

func TestGatewayTagsFilter(t *testing.T) {
	t.Parallel()

	newApiWithTags := func(enabled bool, tags []string) *apidef.APIDefinition {
		return &apidef.APIDefinition{
			TagsDisabled: !enabled,
			Tags:         tags,
		}
	}

	data := &model.MergedAPIList{}
	data.SetClassic([]*apidef.APIDefinition{
		newApiWithTags(false, []string{}),
		newApiWithTags(true, []string{}),
		newApiWithTags(true, []string{"a", "b", "c"}),
		newApiWithTags(true, []string{"a", "b"}),
		newApiWithTags(true, []string{"a"}),
	})

	assert.Len(t, data.Message, 5)

	// Test NodeIsSegmented=false
	{
		enabled := false
		assert.Len(t, data.Filter(enabled), 5)
		assert.Len(t, data.Filter(enabled, "a"), 5)
		assert.Len(t, data.Filter(enabled, "b"), 5)
		assert.Len(t, data.Filter(enabled, "c"), 5)
	}

	// Test NodeIsSegmented=true
	{
		enabled := true
		assert.Len(t, data.Filter(enabled), 0)
		assert.Len(t, data.Filter(enabled, "a"), 3)
		assert.Len(t, data.Filter(enabled, "b"), 2)
		assert.Len(t, data.Filter(enabled, "c"), 1)
	}

	// Test NodeIsSegmented=true, multiple gw tags
	{
		enabled := true
		assert.Len(t, data.Filter(enabled), 0)
		assert.Len(t, data.Filter(enabled, "a", "b"), 3)
		assert.Len(t, data.Filter(enabled, "b", "c"), 2)
	}
}

func TestBlacklist(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/blacklist/literal",
						"method_actions": {"GET": {"action": "no_action"}}
					},
					{
						"path": "/blacklist/{id}/test",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.BlackList)
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/blacklist/literal", Code: http.StatusForbidden},
			{Path: "/blacklist/123/test", Code: http.StatusForbidden},

			{Path: "/blacklist/123/different", Code: http.StatusOK},
			// POST method not blacklisted
			{Method: "POST", Path: "/blacklist/literal", Code: http.StatusOK},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.BlackList = []string{"/blacklist/literal", "/blacklist/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/blacklist/literal", Code: http.StatusForbidden},
			{Path: "/blacklist/123/test", Code: http.StatusForbidden},

			{Path: "/blacklist/123/different", Code: http.StatusOK},
			// POST method also blacklisted
			{Method: "POST", Path: "/blacklist/literal", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Case Sensitivity", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.BlackList = []string{"/Foo", "/bar"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusOK},
			{Path: "/Foo", Code: http.StatusForbidden},
			{Path: "/bar", Code: http.StatusForbidden},
			{Path: "/Bar", Code: http.StatusOK},
		}...)
	})

	t.Run("Listen path matches", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.BlackList = []string{"/fruits/fruit"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/fruits/"
		}, func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.BlackList = []string{"/vegetable$"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/vegetables/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/fruits/fruit", Code: http.StatusForbidden},
			{Path: "/fruits/count", Code: http.StatusOK},

			{Path: "/vegetables/vegetable", Code: http.StatusForbidden},
			{Path: "/vegetables/count", Code: http.StatusOK},
		}...)
	})

	t.Run("Disabled", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths.BlackList = []apidef.EndPointMeta{
					{Disabled: false, Path: "/foo"},
					{Disabled: true, Path: "/bar"},
				}
			})

			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusForbidden},
			{Path: "/bar", Code: http.StatusOK},
		}...)
	})
}

func TestConflictingPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			json.Unmarshal([]byte(`[
				{
					"path": "/metadata/{id}",
					"method_actions": {"GET": {"action": "no_action"}}
				},
				{
					"path": "/metadata/purge",
					"method_actions": {"POST": {"action": "no_action"}}
				}
			]`), &v.ExtendedPaths.WhiteList)
		})

		spec.Proxy.ListenPath = "/"
	})

	ts.Run(t, []test.TestCase{
		// Should ignore auth check
		{Method: "POST", Path: "/metadata/purge", Code: http.StatusOK},
		{Method: "GET", Path: "/metadata/{id}", Code: http.StatusOK},
	}...)
}

func TestIgnored(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.HttpServerOptions.EnablePathPrefixMatching = true
	})
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/ignored/literal",
						"method_actions": {"GET": {"action": "no_action"}}
					},
					{
						"path": "/ignored/{id}/test",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.Ignored)
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should ignore auth check
			{Path: "/ignored/literal", Code: http.StatusOK},
			{Path: "/ignored/123/test", Code: http.StatusOK},
			// Only GET is ignored
			{Method: "POST", Path: "/ext/ignored/literal", Code: http.StatusUnauthorized},

			{Path: "/", Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.Ignored = []string{"/ignored/literal", "/ignored/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should ignore auth check
			{Path: "/ignored/literal", Code: http.StatusOK},
			{Path: "/ignored/123/test", Code: http.StatusOK},

			{Method: "POST", Path: "/ext/ignored/literal", Code: http.StatusUnauthorized},

			{Path: "/", Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("With URL rewrite", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
					Path:         "/ignored",
					Method:       "GET",
					MatchPattern: "/ignored",
					RewriteTo:    "/get",
				}}
				v.ExtendedPaths.Ignored = []apidef.EndPointMeta{
					{
						Path: "ignored",
						MethodActions: map[string]apidef.EndpointMethodMeta{
							http.MethodGet: {
								Action: apidef.NoAction,
								Code:   http.StatusOK,
							},
						},
					},
				}
				v.UseExtendedPaths = true
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			// URL rewrite should work with ignore
			{Path: "/ignored", BodyMatch: `"URI":"/get"`, Code: http.StatusOK},
			{Path: "/", Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("Case Sensitivity", func(t *testing.T) {
		spec := BuildAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.Ignored = []apidef.EndPointMeta{{Path: "/Foo", IgnoreCase: false}, {Path: "/bar", IgnoreCase: true}}
				v.UseExtendedPaths = true
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		ts.Gw.LoadAPI(spec)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusUnauthorized},
			{Path: "/Foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusOK},
			{Path: "/Bar", Code: http.StatusOK},
		}...)

		t.Run("ignore-case globally", func(t *testing.T) {
			spec.Name = "ignore endpoint case globally"
			globalConf := ts.Gw.GetConfig()
			globalConf.IgnoreEndpointCase = true
			ts.Gw.SetConfig(globalConf)

			ts.Gw.LoadAPI(spec)

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK},
				{Path: "/Foo", Code: http.StatusOK},
				{Path: "/bar", Code: http.StatusOK},
				{Path: "/Bar", Code: http.StatusOK},
			}...)
		})

		t.Run("ignore-case in api level", func(t *testing.T) {
			globalConf := ts.Gw.GetConfig()
			globalConf.IgnoreEndpointCase = false
			ts.Gw.SetConfig(globalConf)

			v := spec.VersionData.Versions["v1"]
			v.IgnoreEndpointCase = true
			spec.VersionData.Versions["v1"] = v

			spec.Name = "ignore endpoint in api level"
			ts.Gw.LoadAPI(spec)

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK},
				{Path: "/Foo", Code: http.StatusOK},
				{Path: "/bar", Code: http.StatusOK},
				{Path: "/Bar", Code: http.StatusOK},
			}...)
		})

		// Check whether everything returns normal
		globalConf := ts.Gw.GetConfig()
		globalConf.IgnoreEndpointCase = false
		ts.Gw.SetConfig(globalConf)

		v := spec.VersionData.Versions["v1"]
		v.IgnoreEndpointCase = false
		spec.VersionData.Versions["v1"] = v

		ts.Gw.LoadAPI(spec)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusUnauthorized},
			{Path: "/Foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusOK},
			{Path: "/Bar", Code: http.StatusOK},
		}...)
	})

	t.Run("Disabled", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths.Ignored = []apidef.EndPointMeta{
					{Disabled: false, Path: "/foo"},
					{Disabled: true, Path: "/bar"},
				}
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusUnauthorized},
		}...)
	})
}

func TestOldMockResponse(t *testing.T) {
	test.Racy(t) // TODO: TT-5225

	ts := StartTest(nil)
	defer ts.Close()

	const mockResponse = "this is mock response body"
	const whiteMockPath = "/white-mock"
	const blackMockPath = "/black-mock"
	const ignoredMockPath = "/ignored-mock"

	headers := map[string]string{
		"mock-header": "mock-value",
	}

	whiteEndpointMeta := apidef.EndPointMeta{
		Disabled: false,
		Path:     whiteMockPath,
		MethodActions: map[string]apidef.EndpointMethodMeta{
			"GET": {
				Action:  apidef.Reply,
				Code:    http.StatusTeapot,
				Data:    mockResponse,
				Headers: headers,
			},
			"POST": {
				Action:  apidef.NoAction,
				Code:    http.StatusTeapot,
				Data:    mockResponse,
				Headers: headers,
			},
		},
	}
	blackEndpointMeta := whiteEndpointMeta
	blackEndpointMeta.Path = blackMockPath
	ignoreEndpointMeta := whiteEndpointMeta
	ignoreEndpointMeta.Path = ignoredMockPath

	buildAPI := func(keyless bool, st URLStatus) *APISpec {
		return BuildAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				if st == WhiteList {
					v.ExtendedPaths.WhiteList = []apidef.EndPointMeta{whiteEndpointMeta}
				} else if st == BlackList {
					v.ExtendedPaths.BlackList = []apidef.EndPointMeta{blackEndpointMeta}
				} else if st == Ignored {
					v.ExtendedPaths.Ignored = []apidef.EndPointMeta{ignoreEndpointMeta}
				}

				v.UseExtendedPaths = true
			})

			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = keyless
		})[0]
	}

	check := func(t *testing.T, api *APISpec, tc []test.TestCase) {
		t.Helper()
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, tc...)

		t.Run("migration", func(t *testing.T) {
			_, err := api.Migrate()
			assert.NoError(t, err)

			ts.Gw.LoadAPI(api)
			_, _ = ts.Run(t, tc...)
		})
	}

	t.Run("whitelist", func(t *testing.T) {
		t.Run("keyless", func(t *testing.T) {
			check(t, buildAPI(true, WhiteList), []test.TestCase{
				{Method: http.MethodGet, Path: whiteMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: whiteMockPath, BodyNotMatch: mockResponse, Code: http.StatusOK},
				{Method: http.MethodPut, Path: whiteMockPath, Code: http.StatusForbidden},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusForbidden},
			})
		})

		t.Run("protected", func(t *testing.T) {
			check(t, buildAPI(false, WhiteList), []test.TestCase{
				{Method: http.MethodGet, Path: whiteMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: whiteMockPath, Code: http.StatusUnauthorized},
				{Method: http.MethodPut, Path: whiteMockPath, Code: http.StatusForbidden},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusForbidden},
			})
		})
	})

	t.Run("blacklist", func(t *testing.T) {
		t.Run("keyless", func(t *testing.T) {
			check(t, buildAPI(true, BlackList), []test.TestCase{
				{Method: http.MethodGet, Path: blackMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: blackMockPath, Code: http.StatusForbidden},
				{Method: http.MethodPut, Path: blackMockPath, Code: http.StatusOK},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusOK},
			})
		})

		t.Run("protected", func(t *testing.T) {
			check(t, buildAPI(false, BlackList), []test.TestCase{
				{Method: http.MethodGet, Path: blackMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: blackMockPath, Code: http.StatusForbidden},
				{Method: http.MethodPut, Path: blackMockPath, Code: http.StatusUnauthorized},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusUnauthorized},
			})
		})
	})

	t.Run("ignored", func(t *testing.T) {
		t.Run("keyless", func(t *testing.T) {
			check(t, buildAPI(true, Ignored), []test.TestCase{
				{Method: http.MethodGet, Path: ignoredMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: ignoredMockPath, BodyNotMatch: mockResponse, Code: http.StatusOK},
				{Method: http.MethodPut, Path: ignoredMockPath, Code: http.StatusOK},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusOK},
			})
		})

		t.Run("protected", func(t *testing.T) {
			check(t, buildAPI(false, Ignored), []test.TestCase{
				{Method: http.MethodGet, Path: ignoredMockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
				{Method: http.MethodPost, Path: ignoredMockPath, BodyNotMatch: mockResponse, Code: http.StatusOK},
				{Method: http.MethodPut, Path: ignoredMockPath, Code: http.StatusUnauthorized},
				{Method: http.MethodGet, Path: "/something", Code: http.StatusUnauthorized},
			})
		})
	})
}

func TestNewMockResponse(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const mockResponse = "this is mock response body"
	const mockPath = "/mock"
	headers := map[string]string{
		"mock-header": "mock-value",
	}

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.MockResponse = []apidef.MockResponseMeta{
				{
					Disabled:   false,
					Path:       mockPath,
					IgnoreCase: false,
					Method:     "GET",
					Code:       http.StatusTeapot,
					Body:       mockResponse,
					Headers:    headers,
				},
				{
					Disabled:   false,
					Path:       mockPath,
					IgnoreCase: false,
					Method:     "POST",
					Code:       http.StatusInsufficientStorage,
					Body:       mockResponse,
					Headers:    headers,
				},
			}
			v.UseExtendedPaths = true
		})

		spec.UseKeylessAccess = false

		spec.Proxy.ListenPath = "/"
	})[0]

	t.Run("protected", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodGet, Path: mockPath, BodyMatch: mockResponse, Code: http.StatusTeapot},
		}...)
	})

	t.Run("keyless", func(t *testing.T) {
		api.UseKeylessAccess = true
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodGet, Path: mockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusTeapot},
			{Method: http.MethodPost, Path: mockPath, BodyMatch: mockResponse, HeadersMatch: headers, Code: http.StatusInsufficientStorage},
			{Method: http.MethodPut, Path: mockPath, Code: http.StatusOK},
			{Method: http.MethodGet, Path: "/something", Code: http.StatusOK},
		}...)
	})
}

func TestWhitelistMethodWithAdditionalMiddleware(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"

			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true

				json.Unmarshal([]byte(`[
					{
						"path": "/get",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.WhiteList)
				json.Unmarshal([]byte(`[
					{
						"add_headers": {"foo": "bar"},
						"path": "/get",
						"method": "GET",
						"act_on": false
					}
				]`), &v.ExtendedPaths.TransformResponseHeader)
			})
		})

		//headers := map[string]string{"foo": "bar"}
		ts.Run(t, []test.TestCase{
			//Should get original upstream response
			//{Method: "GET", Path: "/get", Code: http.StatusOK, HeadersMatch: headers},
			//Reject not whitelisted (but know by upstream) path
			{Method: "POST", Path: "/get", Code: http.StatusForbidden},
		}...)
	})
}

func TestSyncAPISpecsDashboardSuccess(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	// Test Dashboard
	tsDash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer tsDash.Close()

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = make(map[string]*APISpec)
	ts.Gw.apisMu.Unlock()

	globalConf := ts.Gw.GetConfig()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = tsDash.URL
	ts.Gw.SetConfig(globalConf)

	var wg sync.WaitGroup
	wg.Add(1)
	msg := testMessageAdapter{Msg: `{"Command": "ApiUpdated"}`}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	ts.Gw.handleRedisEvent(&msg, handled, wg.Done)

	ts.Gw.ReloadTestCase.TickOk(t)
	// Wait for the reload to finish, then check it worked
	wg.Wait()
	ts.Gw.apisMu.RLock()
	defer ts.Gw.apisMu.RUnlock()

	if len(ts.Gw.apisByID) != 1 {
		t.Error("Should return array with one spec", ts.Gw.apisByID)
	}
}

func TestRoundRobin(t *testing.T) {
	rr := RoundRobin{}
	for _, want := range []int{0, 1, 2, 0} {
		if got := rr.WithLen(3); got != want {
			t.Errorf("RR Pos wrong: want %d got %d", want, got)
		}
	}
	if got, want := rr.WithLen(0), 0; got != want {
		t.Errorf("RR Pos of 0 wrong: want %d got %d", want, got)
	}
}

func setupKeepalive(conn net.Conn) error {
	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
		return err
	}
	return nil
}

type customListener struct {
	L net.Listener
}

func (ln *customListener) Init(addr string) (err error) {
	ln.L, err = net.Listen("tcp", addr)
	return
}

func (ln *customListener) Accept() (conn net.Conn, err error) {
	c, err := ln.L.Accept()
	if err != nil {
		return
	}

	if err = setupKeepalive(c); err != nil {
		c.Close()
		return
	}

	handshake := make([]byte, 6)
	if _, err = io.ReadFull(c, handshake); err != nil {
		return
	}

	idLenBuf := make([]byte, 1)
	if _, err = io.ReadFull(c, idLenBuf); err != nil {
		return
	}

	idLen := uint8(idLenBuf[0])
	id := make([]byte, idLen)
	if _, err = io.ReadFull(c, id); err != nil {
		return
	}

	return c, nil
}

func (ln *customListener) Close() error {
	return ln.L.Close()
}

func TestDefaultVersion(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	key, api := ts.testPrepareDefaultVersion()
	authHeaders := map[string]string{"authorization": key}

	ts.Run(t, []test.TestCase{
		{Path: "/foo", Headers: authHeaders, Code: http.StatusForbidden},      // Not whitelisted for default v2
		{Path: "/bar", Headers: authHeaders, Code: http.StatusOK},             // Whitelisted for default v2
		{Path: "/foo?v=v1", Headers: authHeaders, Code: http.StatusOK},        // Allowed for v1
		{Path: "/bar?v=v1", Headers: authHeaders, Code: http.StatusForbidden}, // Not allowed for v1
	}...)

	t.Run("fallback to default", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Path: "/bar?v=notFound", Headers: authHeaders, BodyMatch: string(VersionDoesNotExist), Code: http.StatusForbidden,
		})

		api.VersionDefinition.FallbackToDefault = true
		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, test.TestCase{
			Path: "/bar?v=notFound", Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkDefaultVersion(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	key, _ := ts.testPrepareDefaultVersion()

	authHeaders := map[string]string{"authorization": key}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			[]test.TestCase{
				{Path: "/foo", Headers: authHeaders, Code: http.StatusForbidden},      // Not whitelisted for default v2
				{Path: "/bar", Headers: authHeaders, Code: http.StatusOK},             // Whitelisted for default v2
				{Path: "/foo?v=v1", Headers: authHeaders, Code: http.StatusOK},        // Allowed for v1
				{Path: "/bar?v=v1", Headers: authHeaders, Code: http.StatusForbidden}, // Not allowed for v1
			}...,
		)
	}
}

func (ts *Test) testPrepareDefaultVersion() (string, *APISpec) {

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		v1 := apidef.VersionInfo{Name: "v1"}
		v1.Name = "v1"
		v1.Paths.WhiteList = []string{"/foo"}

		v2 := apidef.VersionInfo{Name: "v2"}
		v2.Paths.WhiteList = []string{"/bar"}

		spec.VersionDefinition.Location = apidef.URLParamLocation
		spec.VersionDefinition.Key = "v"
		spec.VersionData.NotVersioned = false

		spec.VersionData.Versions["v1"] = v1
		spec.VersionData.Versions["v2"] = v2
		spec.VersionData.DefaultVersion = "v2"
		spec.Proxy.ListenPath = "/"

		spec.UseKeylessAccess = false
		spec.DisableRateLimit = true
		spec.DisableQuota = true
	})[0]

	return CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "v2"},
		}}
	}), api
}

func TestGetVersionFromRequest(t *testing.T) {

	versionInfo := apidef.VersionInfo{}
	versionInfo.Paths.WhiteList = []string{"/foo", "/v3/foo"}
	versionInfo.Paths.BlackList = []string{"/bar"}

	t.Run("Header location", func(t *testing.T) {
		ts := StartTest(nil)
		defer func() {
			ts.Close()
		}()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.HeaderLocation
			spec.VersionDefinition.Key = apidef.DefaultAPIVersionKey
			spec.VersionData.Versions["v1"] = versionInfo
		})[0]

		headers := map[string]string{apidef.DefaultAPIVersionKey: "v1"}

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusOK, Headers: headers, BodyMatch: `"X-Api-Version":"v1"`},
			{Path: "/bar", Code: http.StatusForbidden, Headers: headers},
		}...)

		t.Run("strip versioning data", func(t *testing.T) {
			api.VersionDefinition.StripVersioningData = true
			ts.Gw.LoadAPI(api)

			_, _ = ts.Run(t, test.TestCase{Path: "/foo", Code: http.StatusOK, Headers: headers, BodyNotMatch: `"X-Api-Version":"v1"`})
		})
	})

	t.Run("URL param location", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.URLParamLocation
			spec.VersionDefinition.Key = "version"
			spec.VersionData.Versions["v2"] = versionInfo
		})[0]

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo?version=v2", BodyMatch: `"URI":"/foo\?version=v2"`, Code: http.StatusOK},
			{Path: "/bar?version=v2", Code: http.StatusForbidden},
		}...)

		t.Run("strip versioning data", func(t *testing.T) {
			api.VersionDefinition.StripVersioningData = true
			ts.Gw.LoadAPI(api)

			_, _ = ts.Run(t, test.TestCase{Path: "/foo?version=v2", BodyMatch: `"URI":"/foo"`, Code: http.StatusOK})
		})
	})

	t.Run("URL location", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.URLLocation
			spec.VersionData.Versions["v3"] = versionInfo
		})[0]

		ts.Run(t, []test.TestCase{
			{Path: "/v3/foo", BodyMatch: `"URI":"/v3/foo"`, Code: http.StatusOK},
			{Path: "/v3/bar", Code: http.StatusForbidden},
		}...)

		t.Run("strip versioning data", func(t *testing.T) {
			api.VersionDefinition.StripVersioningData = true
			ts.Gw.LoadAPI(api)

			_, _ = ts.Run(t, test.TestCase{Path: "/v3/foo", BodyMatch: `"URI":"/foo"`, Code: http.StatusOK})
		})
	})
}

func BenchmarkGetVersionFromRequest(b *testing.B) {
	b.ReportAllocs()
	ts := StartTest(nil)
	defer ts.Close()

	versionInfo := apidef.VersionInfo{}
	versionInfo.Paths.WhiteList = []string{"/foo"}
	versionInfo.Paths.BlackList = []string{"/bar"}

	b.Run("Header location", func(b *testing.B) {
		b.ReportAllocs()
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.HeaderLocation
			spec.VersionDefinition.Key = apidef.DefaultAPIVersionKey
			spec.VersionData.Versions["v1"] = versionInfo
		})

		headers := map[string]string{apidef.DefaultAPIVersionKey: "v1"}

		for i := 0; i < b.N; i++ {
			ts.Run(b, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK, Headers: headers},
				{Path: "/bar", Code: http.StatusForbidden, Headers: headers},
			}...)
		}
	})

	b.Run("URL param location", func(b *testing.B) {
		b.ReportAllocs()
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.URLParamLocation
			spec.VersionDefinition.Key = "version"
			spec.VersionData.Versions["v2"] = versionInfo
		})

		for i := 0; i < b.N; i++ {
			ts.Run(b, []test.TestCase{
				{Path: "/foo?version=v2", Code: http.StatusOK},
				{Path: "/bar?version=v2", Code: http.StatusForbidden},
			}...)
		}
	})

	b.Run("URL location", func(b *testing.B) {
		b.ReportAllocs()
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = apidef.URLLocation
			spec.VersionData.Versions["v3"] = versionInfo
		})

		for i := 0; i < b.N; i++ {
			ts.Run(b, []test.TestCase{
				{Path: "/v3/foo", Code: http.StatusOK},
				{Path: "/v3/bar", Code: http.StatusForbidden},
			}...)
		}
	})
}

func TestSyncAPISpecsDashboardJSONFailure(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	// Test Dashboard
	callNum := 0
	tsDash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			if callNum == 0 {
				w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
			} else {
				w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": "this is a string"`))
			}

			callNum += 1
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer tsDash.Close()

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = make(map[string]*APISpec)
	ts.Gw.apisMu.Unlock()

	globalConf := ts.Gw.GetConfig()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = tsDash.URL
	ts.Gw.SetConfig(globalConf)

	var wg sync.WaitGroup
	wg.Add(1)
	msg := testMessageAdapter{Msg: `{"Command": "ApiUpdated"}`}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	ts.Gw.handleRedisEvent(&msg, handled, wg.Done)

	ts.Gw.ReloadTestCase.TickOk(t)

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	ts.Gw.apisMu.RLock()
	if len(ts.Gw.apisByID) != 1 {
		t.Error("should return array with one spec", ts.Gw.apisByID)
	}
	ts.Gw.apisMu.RUnlock()

	// Second call

	var wg2 sync.WaitGroup
	wg2.Add(1)
	ts.Gw.ReloadTestCase.Reset()
	ts.Gw.handleRedisEvent(&msg, handled, wg2.Done)

	ts.Gw.ReloadTestCase.TickOk(t)
	// Wait for the reload to finish, then check it worked
	wg2.Wait()
	ts.Gw.apisMu.RLock()
	if len(ts.Gw.apisByID) != 1 {
		t.Error("second call should return array with one spec", ts.Gw.apisByID)
	}
	ts.Gw.apisMu.RUnlock()

}

func TestAPIDefinitionLoader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testTemplatePath = "../templates/transform_test.tmpl"

	l := APIDefinitionLoader{Gw: ts.Gw}

	executeAndAssert := func(t *testing.T, tpl *texttemplate.Template) {
		t.Helper()
		var bodyBuffer bytes.Buffer
		err := tpl.Execute(&bodyBuffer, map[string]string{
			"value1": "value-1",
			"value2": "value-2",
		})
		assert.NoError(t, err)

		var res map[string]string
		_ = json.Unmarshal(bodyBuffer.Bytes(), &res)

		assert.Equal(t, "value-1", res["value2"])
		assert.Equal(t, "value-2", res["value1"])
	}

	t.Run("processRPCDefinitions invalid", func(t *testing.T) {
		specs, err := l.processRPCDefinitions("{invalid json}", ts.Gw)
		assert.Len(t, specs, 0)
		assert.Error(t, err)
	})

	t.Run("processRPCDefinitions zero", func(t *testing.T) {
		specs, err := l.processRPCDefinitions("[]", ts.Gw)
		assert.Len(t, specs, 0)
		assert.NoError(t, err)
	})

	t.Run("loadFileTemplate", func(t *testing.T) {
		temp, err := l.loadFileTemplate(testTemplatePath)
		assert.NoError(t, err)

		executeAndAssert(t, temp)
	})

	t.Run("loadBlobTemplate", func(t *testing.T) {
		templateInBytes, _ := ioutil.ReadFile(testTemplatePath)
		tempBase64 := base64.StdEncoding.EncodeToString(templateInBytes)

		temp, err := l.loadBlobTemplate(tempBase64)
		assert.NoError(t, err)

		executeAndAssert(t, temp)
	})
}

func TestAPIExpiration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.VersionData.NotVersioned = true
		spec.VersionDefinition.Enabled = true
	})[0]

	for _, versioned := range []bool{false, true} {
		api.VersionDefinition.Enabled = versioned

		t.Run(fmt.Sprintf("versioning=%v", versioned), func(t *testing.T) {
			t.Run("not expired", func(t *testing.T) {
				api.Expiration = time.Now().AddDate(1, 0, 0).Format(apidef.ExpirationTimeFormat)
				ts.Gw.LoadAPI(api)
				resp, _ := ts.Run(t, test.TestCase{Code: http.StatusOK})

				assert.NotEmpty(t, resp.Header.Get(XTykAPIExpires))
			})

			t.Run("expired", func(t *testing.T) {
				api.Expiration = apidef.ExpirationTimeFormat
				ts.Gw.LoadAPI(api)
				resp, _ := ts.Run(t, test.TestCase{Code: http.StatusForbidden})

				assert.Empty(t, resp.Header.Get(XTykAPIExpires))
			})
		})
	}
}

func TestAPISpec_SanitizeProxyPaths(t *testing.T) {
	a := APISpec{APIDefinition: &apidef.APIDefinition{}}
	a.Proxy.ListenPath = "/listen/"
	r, _ := http.NewRequest(http.MethodGet, "https://proxy.com/listen/get", nil)

	assert.Equal(t, "/listen/get", r.URL.Path)
	assert.Equal(t, "", r.URL.RawPath)

	t.Run("strip=false", func(t *testing.T) {
		a.SanitizeProxyPaths(r)

		assert.Equal(t, "/listen/get", r.URL.Path)
		assert.Equal(t, "", r.URL.RawPath)
	})

	t.Run("strip=true", func(t *testing.T) {
		a.Proxy.StripListenPath = true
		a.SanitizeProxyPaths(r)

		assert.Equal(t, "/get", r.URL.Path)
		assert.Equal(t, "", r.URL.RawPath)
	})
}

func TestEnforcedTimeout(t *testing.T) {
	test.Flaky(t) // TODO TT-5222

	ts := StartTest(nil)
	defer ts.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.UseKeylessAccess = true
		UpdateAPIVersion(spec, "", func(version *apidef.VersionInfo) {
			version.UseExtendedPaths = true
			version.ExtendedPaths.HardTimeouts = []apidef.HardTimeoutMeta{
				{
					Disabled: false,
					Path:     "/get",
					Method:   http.MethodGet,
					TimeOut:  1,
				},
			}
		})
	})[0]

	ts.Gw.LoadAPI(api)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodGet, Path: "/get", BodyMatch: "Upstream service reached hard timeout", Code: http.StatusGatewayTimeout,
	})

	t.Run("disabled", func(t *testing.T) {
		UpdateAPIVersion(api, "", func(version *apidef.VersionInfo) {
			version.ExtendedPaths.HardTimeouts[0].Disabled = true
		})

		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, test.TestCase{
			Method: http.MethodGet, Path: "/get", Code: http.StatusOK,
		})
	})
}

func TestAPISpec_GetSessionLifetimeRespectsKeyExpiration(t *testing.T) {
	a := APISpec{APIDefinition: &apidef.APIDefinition{}}

	t.Run("GetSessionLifetimeRespectsKeyExpiration=false", func(t *testing.T) {
		a.GlobalConfig.SessionLifetimeRespectsKeyExpiration = false
		a.SessionLifetimeRespectsKeyExpiration = false
		assert.False(t, a.GetSessionLifetimeRespectsKeyExpiration())

		a.SessionLifetimeRespectsKeyExpiration = true
		assert.True(t, a.GetSessionLifetimeRespectsKeyExpiration())
	})

	t.Run("GetSessionLifetimeRespectsKeyExpiration=true", func(t *testing.T) {
		a.GlobalConfig.SessionLifetimeRespectsKeyExpiration = true
		a.SessionLifetimeRespectsKeyExpiration = false
		assert.True(t, a.GetSessionLifetimeRespectsKeyExpiration())

		a.SessionLifetimeRespectsKeyExpiration = true
		assert.True(t, a.GetSessionLifetimeRespectsKeyExpiration())
	})
}

func TestAPISpec_isListeningOnPort(t *testing.T) {
	s := APISpec{APIDefinition: &apidef.APIDefinition{}}
	cfg := &config.Config{}

	cfg.ListenPort = 7000
	assert.True(t, s.isListeningOnPort(7000, cfg))

	s.ListenPort = 8000
	assert.True(t, s.isListeningOnPort(8000, cfg))
}

func Test_LoadAPIsFromRPC(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	objectID := persistentmodel.NewObjectID()
	loader := APIDefinitionLoader{Gw: ts.Gw}

	t.Run("load APIs from RPC - success", func(t *testing.T) {
		mockedStorage := &policy.RPCDataLoaderMock{
			ShouldConnect: true,
			Apis: []model.MergedAPI{
				{APIDefinition: &apidef.APIDefinition{Id: objectID, OrgID: "org1", APIID: "api1"}},
			},
		}

		apisMap, err := loader.FromRPC(mockedStorage, "org1", ts.Gw)

		assert.NoError(t, err, "error loading APIs from RPC:", err)
		assert.Equal(t, 1, len(apisMap), "expected 0 APIs to be loaded from RPC")
	})

	t.Run("load APIs from RPC - success - then fail", func(t *testing.T) {
		mockedStorage := &policy.RPCDataLoaderMock{
			ShouldConnect: true,
			Apis: []model.MergedAPI{
				{APIDefinition: &apidef.APIDefinition{Id: objectID, OrgID: "org1", APIID: "api1"}},
			},
		}
		// we increment the load count by 1, as if we logged in successfully to RPC
		rpc.SetLoadCounts(t, 1)
		defer rpc.SetLoadCounts(t, 0)

		// we load the APIs from RPC successfully - it should store the APIs in the backup
		apisMap, err := loader.FromRPC(mockedStorage, "org1", ts.Gw)

		assert.NoError(t, err, "error loading APIs from RPC:", err)
		assert.Equal(t, 1, len(apisMap), "expected 0 APIs to be loaded from RPC")

		// we now simulate a failure to connect to RPC
		mockedStorage.ShouldConnect = false
		rpc.SetEmergencyMode(t, true)
		defer rpc.ResetEmergencyMode()

		// we now try to load the APIs again, and expect it to load the APIs from the backup
		apisMap, err = loader.FromRPC(mockedStorage, "org1", ts.Gw)

		assert.NoError(t, err, "error loading APIs from RPC:", err)
		assert.Equal(t, 1, len(apisMap), "expected 0 APIs to be loaded from RPC backup")
	})
}

func TestAPISpec_hasMock(t *testing.T) {
	s := APISpec{APIDefinition: &apidef.APIDefinition{}}
	assert.False(t, s.hasActiveMock())

	s.IsOAS = true
	assert.False(t, s.hasActiveMock())

	s.OAS = oas.OAS{}
	assert.False(t, s.hasActiveMock())

	xTyk := &oas.XTykAPIGateway{}
	s.OAS.SetTykExtension(xTyk)
	assert.False(t, s.hasActiveMock())

	middleware := &oas.Middleware{}
	xTyk.Middleware = middleware
	assert.False(t, s.hasActiveMock())

	op := &oas.Operation{}
	middleware.Operations = oas.Operations{
		"my-operation": op,
	}
	assert.False(t, s.hasActiveMock())

	mock := &oas.MockResponse{}
	op.MockResponse = mock
	assert.False(t, s.hasActiveMock())

	mock.Enabled = true
	assert.True(t, s.hasActiveMock())
}

func TestAPISpec_isStreamingAPI(t *testing.T) {
	type testCase struct {
		name           string
		inputOAS       oas.OAS
		expectedResult bool
	}

	testCases := []testCase{
		{
			name:           "should return false if oas is set to default",
			inputOAS:       oas.OAS{},
			expectedResult: false,
		},
		{
			name: "should return false if streaming section is missing",
			inputOAS: oas.OAS{
				T: openapi3.T{
					Extensions: map[string]any{
						"x-tyk-api-gateway": nil,
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "should return true if streaming section is present",
			inputOAS: oas.OAS{
				T: openapi3.T{
					Extensions: map[string]any{
						streams.ExtensionTykStreaming: nil,
						"x-tyk-api-gateway":           nil,
					},
				},
			},
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiSpec := &APISpec{
				OAS: tc.inputOAS,
			}
			assert.Equal(t, tc.expectedResult, apiSpec.isStreamingAPI())
		})
	}
}

func TestReplaceSecrets(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Secrets = map[string]string{
			"Laurentiu": "Ghiur",
		}
	})
	defer ts.Close()

	t.Setenv("Furkan", "Şenharputlu")
	t.Setenv("Leonid", "Bugaev")

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "1"
		spec.JWTSource = "env://Furkan"
		spec.JWTSigningMethod = "secrets://Laurentiu"
	}, func(spec *APISpec) {
		spec.APIID = "2"
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.BasicType: {
				AuthHeaderName: "env://Leonid",
			},
			apidef.AuthTokenType: {
				AuthHeaderName: "env://Furkan",
			},
			apidef.OAuthType: {
				AuthHeaderName: "secrets://Laurentiu",
			},
		}
	})

	api1 := ts.Gw.getApiSpec("1")
	api2 := ts.Gw.getApiSpec("2")
	assert.Equal(t, "Şenharputlu", api1.JWTSource)
	assert.Equal(t, "Bugaev", api2.AuthConfigs[apidef.BasicType].AuthHeaderName)
	assert.Equal(t, "Şenharputlu", api2.AuthConfigs[apidef.AuthTokenType].AuthHeaderName)
	assert.Equal(t, "Ghiur", api1.JWTSigningMethod)
	assert.Equal(t, "Ghiur", api2.AuthConfigs[apidef.OAuthType].AuthHeaderName)
}

func TestInternalEndpointMW_TT_11126(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			assert.NoError(t, json.Unmarshal([]byte(`[
                    {
                        "disabled": false,
                        "add_headers": {
                            "New-Header": "Value"
                        },
                        "path": "/headers",
                        "method": "GET"
                    }
                ]`), &v.ExtendedPaths.TransformHeader))
			assert.NoError(t, json.Unmarshal([]byte(`[
                        {
                            "path": "/headers",
                            "method": "GET",
                            "disabled": false
						}
				]`), &v.ExtendedPaths.Internal))
		})
		spec.Proxy.ListenPath = "/"
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/headers", Code: http.StatusForbidden},
	}...)
}
