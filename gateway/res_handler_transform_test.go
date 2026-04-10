package gateway

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestTransformResponseWithURLRewrite(t *testing.T) {
	transformResponseConf := apidef.TemplateMeta{
		Path:   "get",
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
		},
	}

	urlRewriteConf := apidef.URLRewriteMeta{
		Path:         "abc",
		Method:       "GET",
		MatchPattern: "abc",
		RewriteTo:    "get",
	}

	t.Run("Transform without rewrite", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite to ", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"

			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite path", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"

			transformResponseConf.Path = "abc"

			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/abc", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})
}

func TestTransformResponse_ContextVars(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	transformResponseConf := apidef.TemplateMeta{
		Path:   "get",
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"foo":"{{._tyk_context.headers_Foo}}"}`)),
		},
	}

	// When Context Vars are disabled
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
		})
	})

	ts.Run(t, test.TestCase{
		Headers: map[string]string{"Foo": "Bar"}, Path: "/get", Code: 200, BodyMatch: `{"foo":"<no value>"}`,
	})

	// When Context Vars are enabled
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.EnableContextVars = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
		})
	})

	ts.Run(t, test.TestCase{
		Headers: map[string]string{"Foo": "Bar"}, Path: "/get", Code: 200, BodyMatch: `{"foo":"Bar"}`,
	})
}

func TestTransformResponse_WithCache(t *testing.T) {
	const path = "/get"

	ts := StartTest(nil)
	defer ts.Close()

	transformResponseConf := apidef.TemplateMeta{
		Path:   path,
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"foo":"{{._tyk_context.headers_Foo}}"}`)),
		},
	}

	createAPI := func(withCache bool) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.EnableContextVars = true
			spec.CacheOptions.EnableCache = withCache
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.Cached = []string{path}
			})
		})

	}

	// without cache
	createAPI(false)

	ts.Run(t, []test.TestCase{
		{Path: path, Headers: map[string]string{"Foo": "Bar"}, Code: 200, BodyMatch: `{"foo":"Bar"}`},
		{Path: path, Headers: map[string]string{"Foo": "Bar2"}, Code: 200, BodyMatch: `{"foo":"Bar2"}`},
	}...)

	// with cache
	createAPI(true)

	ts.Run(t, []test.TestCase{
		{Path: path, Headers: map[string]string{"Foo": "Bar"}, Code: 200, BodyMatch: `{"foo":"Bar"}`, Delay: 100 * time.Millisecond}, // Returns response and caches it
		{Path: path, Headers: map[string]string{"Foo": "Bar2"}, Code: 200, BodyMatch: `{"foo":"Bar"}`},                               // Returns cached response directly
	}...)

}

func TestTransformResponseBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	loadAPI := func(disabled bool) {
		transformResponseConf := apidef.TemplateMeta{
			Disabled: disabled,
			Path:     "/transform",
			Method:   http.MethodGet,
			TemplateData: apidef.TemplateData{
				Mode:           "blob",
				TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
			},
		}
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})
	}

	t.Run("transform body enabled", func(t *testing.T) {
		loadAPI(false)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/transform", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("transform body disabled", func(t *testing.T) {
		loadAPI(true)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/transform", Code: 200, BodyNotMatch: `{"http_method":"GET"}`,
		})
	})
}

func TestResponseTransformMiddleware_Enabled(t *testing.T) {
	getTransformResponseConf := func(disabled bool, path string) apidef.TemplateMeta {
		return apidef.TemplateMeta{
			Disabled: disabled,
			Path:     path,
			Method:   http.MethodGet,
			TemplateData: apidef.TemplateData{
				Mode:           "blob",
				TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
			},
		}
	}

	getSpec := func(transformResponseMWs []apidef.TemplateMeta) *APISpec {
		return &APISpec{
			APIDefinition: &apidef.APIDefinition{
				VersionData: apidef.VersionData{
					DefaultVersion: "Default",
					NotVersioned:   true,
					Versions: map[string]apidef.VersionInfo{
						"Default": {
							Name: "Default",
							ExtendedPaths: apidef.ExtendedPathsSet{
								TransformResponse: transformResponseMWs,
							},
						},
					},
				},
			},
		}
	}

	testCases := []struct {
		name      string
		spec      *APISpec
		mwEnabled bool
	}{
		{
			name: "all disabled",
			spec: getSpec([]apidef.TemplateMeta{
				getTransformResponseConf(true, "/transform1"),
				getTransformResponseConf(true, "/transform2"),
			}),
			mwEnabled: false,
		},
		{
			name: "at least one enabled",
			spec: getSpec([]apidef.TemplateMeta{
				getTransformResponseConf(false, "/transform1"),
				getTransformResponseConf(true, "/transform2"),
			}),
			mwEnabled: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responseTransformMW := ResponseTransformMiddleware{
				BaseTykResponseHandler{
					Spec: tc.spec,
				},
			}

			assert.Equal(t, tc.mwEnabled, responseTransformMW.Enabled())
		})
	}
}

func TestHeaderTransformBase(t *testing.T) {
	// Initialize the HeaderTransform
	ht := &HeaderTransform{
		BaseTykResponseHandler: BaseTykResponseHandler{
			// You can populate fields if needed
		},
		config: HeaderTransformOptions{
			// You can populate fields if needed
		},
	}

	// Get the base using the method
	base := ht.Base()

	// Check that the returned base is indeed the BaseTykResponseHandler of ht
	require.Equal(t, &ht.BaseTykResponseHandler, base, "Base method did not return the expected BaseTykResponseHandler")
}

func TestResponseTransformMiddleware(t *testing.T) {
	t.Run("Response transform alone", func(t *testing.T) {
		ts := StartTest(nil)

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"name":"world"}`))
			assert.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))

		t.Cleanup(testServer.Close)
		t.Cleanup(ts.Close)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test"
			spec.Proxy.TargetURL = testServer.URL

			v := spec.VersionData.Versions["Default"]

			v.UseExtendedPaths = true
			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{
				{
					Path:   "/anything/(\\d+)$",
					Method: http.MethodGet,
					TemplateData: apidef.TemplateData{
						Mode:           apidef.UseBlob,
						TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"greeting": "hello {{.name}}"}`)),
						Input:          apidef.RequestJSON,
						EnableSession:  false,
					},
				},
			}

			spec.VersionData.Versions["Default"] = v
		})

		_, _ = ts.Run(t, test.TestCase{
			Path:      "/test/anything/123",
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			BodyMatch: `{"greeting": "hello world"}`,
		})
	})

	t.Run("Response transform with URL rewrite", func(t *testing.T) {
		ts := StartTest(nil)

		type transformedResponse struct {
			Transformed bool   `json:"transformed"`
			Path        string `json:"path"`
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			body, err := json.Marshal(struct {
				Path string `json:"Path"`
			}{
				Path: r.URL.Path,
			})
			require.NoError(t, err)

			_, err = w.Write(body)
			require.NoError(t, err)

			w.WriteHeader(http.StatusOK)
		}))

		t.Cleanup(testServer.Close)
		t.Cleanup(ts.Close)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.TargetURL = testServer.URL
			spec.Proxy.ListenPath = "/combined/"
			v := spec.VersionData.Versions["Default"]

			v.UseExtendedPaths = true
			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{
				{
					Path:         "/anything/(\\d+)$",
					Method:       "GET",
					MatchPattern: "/anything/(\\d+)$",
					RewriteTo:    "/anything/transformed/$1",
				},
			}

			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{
				{
					Path:   "/anything/(\\d+)$",
					Method: "GET",
					TemplateData: apidef.TemplateData{
						Mode:           apidef.UseBlob,
						TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"transformed": true, "path": "{{.Path}}"}`)),
						Input:          apidef.RequestJSON,
						EnableSession:  false,
					},
				},
			}

			spec.VersionData.Versions["Default"] = v
		})

		res, err := ts.Run(t, test.TestCase{
			Path:   "/combined/anything/7777",
			Method: http.MethodGet,
			Code:   http.StatusOK,
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		rawBody, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		var body transformedResponse
		assert.NoError(t, json.Unmarshal(rawBody, &body))
		assert.Equal(t, transformedResponse{
			Transformed: true,
			Path:        "/anything/transformed/7777",
		}, body)
	})

	t.Run("with body size constraints", func(t *testing.T) {
		testCases := []struct {
			name             string
			maxBodySize      int64
			responseBody     string
			expectTransform  bool
			expectedResponse string
			expectedCode     int
			expectedError    string
		}{
			{
				name:             "Response body within limit",
				maxBodySize:      100,
				responseBody:     `{"name":"test"}`,
				expectTransform:  true,
				expectedResponse: `{"result": "test"}`,
				expectedCode:     http.StatusOK,
			},
			{
				name:          "Response body exceeds limit",
				maxBodySize:   10,
				responseBody:  `{"name":"this is a long response that exceeds the limit"}`,
				expectedCode:  http.StatusInternalServerError,
				expectedError: "Response body too large",
			},
			{
				name:             "Constraint disabled (zero value)",
				maxBodySize:      0,
				responseBody:     `{"name":"test"}`,
				expectTransform:  true,
				expectedResponse: `{"result": "test"}`,
				expectedCode:     http.StatusOK,
			},
			{
				name:             "Exact limit boundary",
				maxBodySize:      15,
				responseBody:     `{"name":"test"}`,
				expectTransform:  true,
				expectedResponse: `{"result": "test"}`,
				expectedCode:     http.StatusOK,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ts := StartTest(func(globalConf *config.Config) {
					globalConf.HttpServerOptions.MaxResponseBodySize = tc.maxBodySize
				})
				defer ts.Close()

				testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, err := w.Write([]byte(tc.responseBody))
					assert.NoError(t, err)
				}))
				defer testServer.Close()

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.Proxy.ListenPath = "/test"
					spec.Proxy.TargetURL = testServer.URL

					UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
						v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{
							{
								Path:   "/transform",
								Method: http.MethodGet,
								TemplateData: apidef.TemplateData{
									Mode:           apidef.UseBlob,
									TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"result": "{{.name}}"}`)),
									Input:          apidef.RequestJSON,
								},
							},
						}
					})
				})

				res, err := ts.Run(t, test.TestCase{
					Path:   "/test/transform",
					Method: http.MethodGet,
					Code:   tc.expectedCode,
				})

				require.NoError(t, err)
				assert.Equal(t, tc.expectedCode, res.StatusCode)

				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)

				if tc.expectTransform {
					assert.JSONEq(t, tc.expectedResponse, string(body))
				}

				if tc.expectedError != "" {
					assert.Contains(t, string(body), tc.expectedError)
				}
			})
		}
	})
}
