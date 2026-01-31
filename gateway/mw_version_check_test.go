package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func (ts *Test) testPrepareVersioning() (string, string) {

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.VersionData.NotVersioned = false
		spec.VersionDefinition.Location = "header"
		spec.VersionDefinition.Key = "version"
		spec.Proxy.ListenPath = "/"
		spec.DisableRateLimit = true
		spec.DisableQuota = true
		spec.VersionData.Versions["expired"] = apidef.VersionInfo{
			Name:    "expired",
			Expires: "2006-01-02 15:04",
		}
		spec.VersionData.Versions["v2"] = apidef.VersionInfo{
			Name:             "v2",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				WhiteList: []apidef.EndPointMeta{
					{
						Path: "/mock",
						MethodActions: map[string]apidef.EndpointMethodMeta{
							http.MethodGet: {
								Action:  apidef.Reply,
								Code:    http.StatusOK,
								Data:    "testbody",
								Headers: map[string]string{"testheader": "testvalue"},
							},
						},
					},
				},
				URLRewrite: []apidef.URLRewriteMeta{
					{
						Path:         "/a",
						Method:       http.MethodGet,
						MatchPattern: "/a(.*)",
						RewriteTo:    "/b",
					},
					{
						Path:         "/c",
						Method:       http.MethodPost,
						MatchPattern: "/c(.*)",
						RewriteTo:    "/d",
					},
				},
				Ignored: []apidef.EndPointMeta{
					{
						Path: "/ignore",
					},
				},
			},
		}
	})

	keyWrongVersion := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v3"},
		}}
	})

	keyKnownVersion := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "v2", "expired"},
		}}
	})

	return keyWrongVersion, keyKnownVersion
}

func TestVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := ts.testPrepareVersioning()

	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v3",
	}

	disallowedAccessHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v1",
	}

	knownVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v1",
	}

	expiredVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "expired",
	}

	mockVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v2",
	}

	ts.Run(t, []test.TestCase{
		{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
		{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
		{Path: "/", Code: 200, Headers: knownVersionHeaders},
		{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
		{Path: "/mock", Code: 200, Headers: mockVersionHeaders, BodyMatch: "testbody", HeadersMatch: map[string]string{"testheader": "testvalue"}},
		{Path: "/ignore", Code: 200, Headers: mockVersionHeaders},
	}...)
}

func BenchmarkVersioning(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := ts.testPrepareVersioning()
	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v3",
	}

	disallowedAccessHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v1",
	}

	knownVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v1",
	}

	expiredVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "expired",
	}
	mockVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v2",
	}

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
			{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
			{Path: "/", Code: 200, Headers: knownVersionHeaders},
			{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
			{Path: "/mock", Code: 200, Headers: mockVersionHeaders, BodyMatch: "testbody", HeadersMatch: map[string]string{"testheader": "testvalue"}},
			{Path: "/ignore", Code: 200, Headers: mockVersionHeaders},
		}...)
	}
}

func TestNotVersioned(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:           "Default",
			OverrideTarget: "www.example.com",
		}
	})[0]

	t.Run("Versioning enabled, override target URL", func(t *testing.T) {
		g.Gw.LoadAPI(api)
		_, _ = g.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})

	t.Run("Versioning disabled, use original target URL", func(t *testing.T) {
		api.VersionData.NotVersioned = true
		g.Gw.LoadAPI(api)

		_, _ = g.Run(t, test.TestCase{Code: http.StatusOK})
	})
}

func TestNewVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		baseVersionName = "base-version-name"
		v1APIID         = "v1-api-id"
		v1VersionName   = "v1-version-name"
		v2APIID         = "v2-api-id"
		v2VersionName   = "v2-version-name"
	)

	baseAPI := BuildAPI(func(a *APISpec) {
		a.APIID = "base"
		a.Proxy.ListenPath = "/default"
		a.UseKeylessAccess = true
		a.VersionDefinition.Enabled = true
		a.VersionDefinition.Name = baseVersionName
		a.VersionDefinition.Default = apidef.Self
		a.VersionDefinition.Location = apidef.URLParamLocation
		a.VersionDefinition.Key = "version"
		a.VersionDefinition.Versions = map[string]string{
			v1VersionName: v1APIID,
			v2VersionName: v2APIID,
		}
	})[0]

	v1 := BuildAPI(func(a *APISpec) {
		a.APIID = v1APIID
		a.Name = "v1-api-name"
		a.Proxy.ListenPath = "/v1-listen-path"
		a.UseKeylessAccess = false
	})[0]

	v2 := BuildAPI(func(a *APISpec) {
		a.APIID = v2APIID
		a.Name = "v2-api-name"
		a.Proxy.ListenPath = "/v2-listen-path"
		a.UseKeylessAccess = false
	})[0]

	ts.Gw.LoadAPI(baseAPI, v1, v2)

	_, v1APIkey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{v1.APIID: {
			APIID: v1.APIID,
		}}
	})

	_, baseAPIKey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{baseAPI.APIID: {
			APIID: baseAPI.APIID, Versions: []string{v1VersionName},
		}}
	})

	headersForV1 := map[string]string{
		"Authorization": v1APIkey,
	}

	headersForBaseAPI := map[string]string{
		"Authorization": baseAPIKey,
	}

	t.Run("default version can be self", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default", Code: http.StatusOK})
	})

	t.Run("sub-version should be accessible when default is self", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=" + v2VersionName, Code: http.StatusUnauthorized})
	})

	baseAPI.VersionDefinition.Default = v1VersionName
	ts.Gw.LoadAPI(baseAPI, v1, v2)
	t.Run("sub-version should be accessible without version param when it is default", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default", Code: http.StatusUnauthorized})
	})

	t.Run("base should be accessible with its name when sub-version is default", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=" + baseVersionName, Code: http.StatusOK})
	})

	t.Run("invalid version in param should give error", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=notFound", BodyMatch: string(VersionDoesNotExist), Code: http.StatusNotFound})
	})

	t.Run("fallback to default", func(t *testing.T) {
		baseAPI.VersionDefinition.Default = baseVersionName
		baseAPI.VersionDefinition.FallbackToDefault = true
		ts.Gw.LoadAPI(baseAPI, v1, v2)

		// fallback to base
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=notFound", Code: http.StatusOK})

		baseAPI.VersionDefinition.Default = apidef.Self
		baseAPI.VersionDefinition.FallbackToDefault = true
		ts.Gw.LoadAPI(baseAPI, v1, v2)

		// fallback to base
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=notFound", Code: http.StatusOK})

		baseAPI.VersionDefinition.Default = v1VersionName
		baseAPI.VersionDefinition.FallbackToDefault = true
		ts.Gw.LoadAPI(baseAPI, v1, v2)

		// fallback to v1
		_, _ = ts.Run(t, test.TestCase{Path: "/default?version=notFound", Code: http.StatusUnauthorized})
	})

	t.Run("accessing to sub-version with base API listen path should require base API key", func(t *testing.T) {
		t.SkipNow()
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/default?version=" + v1VersionName, Headers: headersForV1, Code: http.StatusForbidden},
			{Path: "/default?version=" + v1VersionName, Headers: headersForBaseAPI, Code: http.StatusOK},
		}...)
	})

	t.Run("sub-version should be accessible with param if has access rights", func(t *testing.T) {
		t.SkipNow()
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/default?version=" + v2VersionName, Headers: headersForBaseAPI, Code: http.StatusForbidden},
			{Path: "/default?version=" + v1VersionName, Headers: headersForBaseAPI, Code: http.StatusOK},
		}...)
	})

	t.Run("sub-version should be accessible in its own listen path", func(t *testing.T) {
		t.Run("key checks", func(t *testing.T) {
			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/v1-listen-path", Code: http.StatusUnauthorized},
				{Path: "/v1-listen-path", Headers: headersForV1, Code: http.StatusOK},
			}...)
		})
	})
}

func TestOldVersioning_DefaultVersionEmpty(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.VersionData.NotVersioned = false
		spec.VersionData.DefaultVersion = ""
		spec.VersionData.Versions = map[string]apidef.VersionInfo{
			"v1": {
				UseExtendedPaths: true,
				ExtendedPaths: apidef.ExtendedPathsSet{
					WhiteList: []apidef.EndPointMeta{
						{
							Path: "/",
							MethodActions: map[string]apidef.EndpointMethodMeta{
								http.MethodGet: {
									Action: apidef.Reply,
									Data:   "v1",
									Code:   http.StatusOK,
								},
							},
						},
					},
				},
			},
			"v2": {},
		}
		spec.VersionDefinition.Location = apidef.URLLocation
	})[0]

	check := func(t *testing.T, tc []test.TestCase, apis ...*APISpec) {
		t.Helper()
		ts.Gw.LoadAPI(apis...)
		_, _ = ts.Run(t, tc...)
	}

	cases := []test.TestCase{
		{Path: "/", BodyMatch: string(VersionNotFound), Code: http.StatusForbidden},
		{Path: "/v1/", BodyMatch: "v1", Code: http.StatusOK},
	}

	check(t, cases, api)

	t.Run("migration", func(t *testing.T) {
		versions, err := api.MigrateVersioning()
		assert.NoError(t, err)

		var apis []*APISpec
		apis = append(apis, api, &APISpec{APIDefinition: &versions[0]})

		check(t, cases, apis...)
	})
}

func TestOldVersioning_StripPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := func() *APISpec {
		return BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionData.DefaultVersion = "Default"
			spec.VersionData.Versions = map[string]apidef.VersionInfo{
				"Default": {},
				"v1":      {},
			}
			spec.VersionDefinition.Location = apidef.URLLocation
			spec.VersionDefinition.StripPath = false
		})[0]
	}

	check := func(t *testing.T, api *APISpec, tc test.TestCase) {
		t.Helper()
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, tc)

		t.Run("migration", func(t *testing.T) {
			versions, err := api.MigrateVersioning()
			assert.NoError(t, err)

			ts.Gw.LoadAPI(api, &APISpec{APIDefinition: &versions[0]})
			_, _ = ts.Run(t, tc)
		})
	}

	t.Run("StripPath=false", func(t *testing.T) {
		check(t, api(), test.TestCase{Path: "/v1/", BodyMatch: `"URI":"/v1/"`, Code: http.StatusOK})
	})

	t.Run("StripPath=true", func(t *testing.T) {
		a := api()
		a.VersionDefinition.StripPath = true
		check(t, a, test.TestCase{Path: "/v1/", BodyMatch: `"URI":"/"`, Code: http.StatusOK})
	})
}

func TestOldVersioning_Expires(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	nextYear := time.Now().AddDate(1, 0, 1)

	vInfo := apidef.VersionInfo{
		Expires: nextYear.Format(apidef.ExpirationTimeFormat),
	}

	api := func() *APISpec {
		return BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = true
			spec.VersionData.DefaultVersion = "Default"
			spec.VersionDefinition.Location = apidef.URLParamLocation
			spec.VersionDefinition.Key = "version"
			spec.VersionData.Versions = map[string]apidef.VersionInfo{
				"Default": vInfo,
			}
		})[0]
	}

	check := func(t *testing.T, api *APISpec, tc test.TestCase, expirationHeaderEmpty bool) {
		t.Helper()
		subCheck := func(t *testing.T, apis ...*APISpec) {
			t.Helper()
			ts.Gw.LoadAPI(apis...)
			resp, _ := ts.Run(t, tc)

			if expirationHeaderEmpty {
				assert.Empty(t, resp.Header.Get(XTykAPIExpires))
			} else {
				// In migration, there is one behavior change that if old api is not versioned but `expires` is set,
				// it was setting expiration header. However, in new expiration feature, it means empty expiration. So, it
				// should result in empty XTykAPIExpires header.
				if _, ok := api.VersionData.Versions[""]; !ok {
					assert.NotEmpty(t, resp.Header.Get(XTykAPIExpires))
				}
			}
		}

		subCheck(t, api)

		t.Run("migration", func(t *testing.T) {
			versions, err := api.MigrateVersioning()
			assert.NoError(t, err)

			apis := []*APISpec{api}
			if len(versions) > 0 {
				apis = append(apis, &APISpec{APIDefinition: &versions[0]})
			}

			subCheck(t, apis...)
		})
	}

	t.Run("old versioning disabled", func(t *testing.T) {
		t.Run("not expired", func(t *testing.T) {
			check(t, api(), test.TestCase{Code: http.StatusOK}, false)
		})

		t.Run("expired", func(t *testing.T) {
			vInfo.Expires = apidef.ExpirationTimeFormat
			expiredAPI := api()
			expiredAPI.VersionData.Versions["Default"] = vInfo

			check(t, expiredAPI, test.TestCase{Code: http.StatusOK}, true)
		})
	})

	t.Run("old versioning enabled", func(t *testing.T) {
		t.Run("base", func(t *testing.T) {
			t.Run("not expired", func(t *testing.T) {
				versionedNotExpired := api()
				versionedNotExpired.VersionData.NotVersioned = false
				vInfo.Expires = nextYear.Format(apidef.ExpirationTimeFormat)
				versionedNotExpired.VersionData.Versions["Default"] = vInfo

				check(t, versionedNotExpired, test.TestCase{Code: http.StatusOK}, false)
			})

			t.Run("expired", func(t *testing.T) {
				versionedExpired := api()
				versionedExpired.VersionData.NotVersioned = false
				vInfo.Expires = apidef.ExpirationTimeFormat
				versionedExpired.VersionData.Versions["Default"] = vInfo

				check(t, versionedExpired, test.TestCase{Code: http.StatusForbidden}, true)
			})
		})

		t.Run("sub-version", func(t *testing.T) {
			t.Run("not expired", func(t *testing.T) {
				versionedNotExpired := api()
				versionedNotExpired.VersionData.NotVersioned = false
				vInfo.Expires = nextYear.Format(apidef.ExpirationTimeFormat)
				versionedNotExpired.VersionData.Versions["v1"] = vInfo
				versionedNotExpired.VersionData.Versions["Default"] = vInfo

				check(t, versionedNotExpired, test.TestCase{Path: "/?version=v1", Code: http.StatusOK}, false)
			})

			t.Run("expired", func(t *testing.T) {
				versionedExpired := api()
				versionedExpired.VersionData.NotVersioned = false
				vInfo.Expires = apidef.ExpirationTimeFormat
				versionedExpired.VersionData.Versions["v1"] = vInfo
				versionedExpired.VersionData.Versions["Default"] = vInfo

				check(t, versionedExpired, test.TestCase{Path: "/?version=v1", Code: http.StatusForbidden}, true)
			})
		})
	})
}

func TestVersionCheck_getPrimitiveAllowListFlag(t *testing.T) {
	tests := []struct {
		name                      string
		path                      string
		toolsAllowListEnabled     bool
		resourcesAllowListEnabled bool
		promptsAllowListEnabled   bool
		expected                  bool
	}{
		{
			name:                      "tool prefix with allowlist enabled",
			path:                      mcp.ToolPrefix + "get-weather",
			toolsAllowListEnabled:     true,
			resourcesAllowListEnabled: false,
			promptsAllowListEnabled:   false,
			expected:                  true,
		},
		{
			name:                      "tool prefix with allowlist disabled",
			path:                      mcp.ToolPrefix + "get-weather",
			toolsAllowListEnabled:     false,
			resourcesAllowListEnabled: false,
			promptsAllowListEnabled:   false,
			expected:                  false,
		},
		{
			name:                      "resource prefix with allowlist enabled",
			path:                      mcp.ResourcePrefix + "file:///config.json",
			toolsAllowListEnabled:     false,
			resourcesAllowListEnabled: true,
			promptsAllowListEnabled:   false,
			expected:                  true,
		},
		{
			name:                      "resource prefix with allowlist disabled",
			path:                      mcp.ResourcePrefix + "file:///config.json",
			toolsAllowListEnabled:     false,
			resourcesAllowListEnabled: false,
			promptsAllowListEnabled:   false,
			expected:                  false,
		},
		{
			name:                      "prompt prefix with allowlist enabled",
			path:                      mcp.PromptPrefix + "code-review",
			toolsAllowListEnabled:     false,
			resourcesAllowListEnabled: false,
			promptsAllowListEnabled:   true,
			expected:                  true,
		},
		{
			name:                      "prompt prefix with allowlist disabled",
			path:                      mcp.PromptPrefix + "code-review",
			toolsAllowListEnabled:     false,
			resourcesAllowListEnabled: false,
			promptsAllowListEnabled:   false,
			expected:                  false,
		},
		{
			name:                      "non-MCP path returns false",
			path:                      "/regular-path",
			toolsAllowListEnabled:     true,
			resourcesAllowListEnabled: true,
			promptsAllowListEnabled:   true,
			expected:                  false,
		},
		{
			name:                      "empty path returns false",
			path:                      "",
			toolsAllowListEnabled:     true,
			resourcesAllowListEnabled: true,
			promptsAllowListEnabled:   true,
			expected:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VersionCheck{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition:             &apidef.APIDefinition{},
						ToolsAllowListEnabled:     tt.toolsAllowListEnabled,
						ResourcesAllowListEnabled: tt.resourcesAllowListEnabled,
						PromptsAllowListEnabled:   tt.promptsAllowListEnabled,
					},
				},
			}

			result := v.getPrimitiveAllowListFlag(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVersionCheck_checkVEMWhiteListEntry(t *testing.T) {
	conf := config.Config{
		HttpServerOptions: config.HttpServerOptionsConfig{
			EnablePathPrefixMatching: true,
			EnablePathSuffixMatching: true,
		},
	}
	loader := APIDefinitionLoader{}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}

	tests := []struct {
		name           string
		path           string
		whitelistPaths []apidef.EndPointMeta
		errorMessage   string
		expectError    bool
	}{
		{
			name: "whitelist entry found - exact match",
			path: mcp.ToolPrefix + "get-weather",
			whitelistPaths: []apidef.EndPointMeta{
				{Path: mcp.ToolPrefix + "get-weather", Method: http.MethodPost},
			},
			errorMessage: "Access denied",
			expectError:  false,
		},
		{
			name: "whitelist entry not found",
			path: mcp.ToolPrefix + "delete-database",
			whitelistPaths: []apidef.EndPointMeta{
				{Path: mcp.ToolPrefix + "get-weather", Method: http.MethodPost},
			},
			errorMessage: "Access denied",
			expectError:  true,
		},
		{
			name:           "empty version paths",
			path:           mcp.ToolPrefix + "get-weather",
			whitelistPaths: []apidef.EndPointMeta{},
			errorMessage:   "No access",
			expectError:    true,
		},
		{
			name: "multiple entries - match found",
			path: mcp.ResourcePrefix + "file:///config.json",
			whitelistPaths: []apidef.EndPointMeta{
				{Path: mcp.ToolPrefix + "get-weather", Method: http.MethodPost},
				{Path: mcp.ResourcePrefix + "file:///config.json", Method: http.MethodPost},
				{Path: mcp.PromptPrefix + "code-review", Method: http.MethodPost},
			},
			errorMessage: "Access denied",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build URLSpecs using the loader
			versionPaths := loader.compileExtendedPathSpec(false, tt.whitelistPaths, WhiteList, conf)

			v := &VersionCheck{BaseMiddleware: &BaseMiddleware{Spec: spec}}
			err := v.checkVEMWhiteListEntry(tt.path, versionPaths, tt.errorMessage)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.errorMessage, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
