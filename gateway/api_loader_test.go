package gateway

import (
	"context"
	"fmt"
	"net/http"
	"path"
	_ "path"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

func TestOpenTracing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	trace.SetupTracing("test", nil)
	defer trace.Close()

	t.Run("ensure the manager is enabled", func(ts *testing.T) {

		if !trace.IsEnabled() {
			ts.Error("expected tracing manager should be enabled")
		}
	})

	t.Run("ensure services are initialized", func(tst *testing.T) {
		var s atomic.Value
		trace.SetInit(func(name string, service string, opts map[string]interface{}, logger trace.Logger) (trace.Tracer, error) {
			s.Store(service)
			return trace.NoopTracer{}, nil
		})
		name := "trace"
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Name = name
				spec.UseOauth2 = true
			},
		)
		var n string
		if v := s.Load(); v != nil {
			n = v.(string)
		}
		if name != n {
			tst.Errorf("expected %s got %s", name, n)
		}
	})
}

func TestInternalAPIUsage(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	internal := BuildAPI(func(spec *APISpec) {
		spec.Name = "internal"
		spec.APIID = "test1"
		spec.Proxy.ListenPath = "/"
	})[0]

	normal := BuildAPI(func(spec *APISpec) {
		spec.Name = "normal"
		spec.APIID = "test2"
		spec.Proxy.TargetURL = fmt.Sprintf("tyk://%s", internal.Name)
		spec.Proxy.ListenPath = "/normal-api"
	})[0]

	g.Gw.LoadAPI(internal, normal)

	t.Run("with name", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})

	t.Run("with api id", func(t *testing.T) {
		normal.Proxy.TargetURL = fmt.Sprintf("tyk://%s", internal.APIID)
		g.Gw.LoadAPI(internal, normal)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})
}

func TestFuzzyFindAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	objectId := model.NewObjectID()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Name = "IgnoreCase"
			spec.APIID = "1"
		},
		func(spec *APISpec) {
			spec.Name = "IgnoreCategories #a #b"
			spec.APIID = "2"
		},
		func(spec *APISpec) {
			spec.Name = "__replace-underscores__"
			spec.APIID = "3"
		},
		func(spec *APISpec) {
			spec.Name = "@@replace-ats@@"
			spec.APIID = "4"
		},
		func(spec *APISpec) {
			spec.Name = "matchByHex"
			spec.APIID = "5"
			spec.Id = objectId
		},
		func(spec *APISpec) {
			spec.Name = "matchByApiID"
			spec.APIID = "6"
		})

	cases := []struct {
		name, search, expectedAPIID string
		expectNil                   bool
	}{
		{"ignore case", "ignoreCase", "1", false},
		{"ignore categories", "IgnoreCategories", "2", false},
		{"replace underscores", "-replace-underscores-", "3", false},
		{"replace @", "-replace-ats-", "4", false},
		{"supply hex", objectId.Hex(), "5", false},
		{"supply APIID", "6", "6", false},
		{"empty search string", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := ts.Gw.fuzzyFindAPI(tc.search)

			if tc.expectNil {
				assert.Nil(t, spec)
			} else {
				assert.Equal(t, tc.expectedAPIID, spec.APIID)
			}
		})
	}
}

func TestAPILoopingName(t *testing.T) {
	cases := []struct {
		apiName, expectedOut string
	}{
		{"api #a #b #c", "api"},
		{"__api #a #b #c", "-api"},
		{"@api #a #b #c", "-api"},
		{"api", "api"},
		{"__api__", "-api-"},
		{"@__ api -_ name @__", "-api-name-"},
		{"@__ api -_ name @__ #a #b", "-api-name-"},
	}

	for _, tc := range cases {
		t.Run(tc.apiName, func(t *testing.T) {
			assert.Equal(t, tc.expectedOut, APILoopingName(tc.apiName))
		})
	}
}

func TestGraphQLPlayground(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const apiName = "graphql-api"

	api := BuildAPI(func(spec *APISpec) {
		spec.APIID = "APIID"
		spec.Proxy.ListenPath = fmt.Sprintf("/%s/", apiName)
		spec.GraphQL.Enabled = true
		spec.GraphQL.GraphQLPlayground.Enabled = true
	})[0]

	run := func(t *testing.T, playgroundPath string, api *APISpec, env string) {
		endpoint := api.Proxy.ListenPath
		if env == "cloud" {
			endpoint = fmt.Sprintf("/%s/", api.Slug)
		}

		t.Run("playground html is loaded", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: playgroundPath, BodyMatch: `<title>API Playground</title>`, Code: http.StatusOK},
				{Path: playgroundPath, BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), fmt.Sprintf(`const url = window.location.origin + "%s";`, endpoint))
				}, Code: http.StatusOK},
			}...)
		})
		t.Run("playground.js is loaded", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: path.Join(playgroundPath, "playground.js"), BodyMatch: "TykGraphiQL", Code: http.StatusOK},
			}...)
		})
		t.Run("should get error on post request to playground path", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:         playgroundPath,
					Method:       http.MethodPost,
					BodyNotMatch: `<title>API Playground</title>`,
					BodyMatch:    `"error": "the provided request is empty"`,
					Code:         http.StatusBadRequest,
				},
			}...)
		})
	}

	for _, env := range []string{"on-premise", "cloud"} {
		if env == "cloud" {
			api.Proxy.ListenPath = fmt.Sprintf("/%s/", api.APIID)
			globalConf := g.Gw.GetConfig()
			api.Slug = "someslug"
			globalConf.Cloud = true
			g.Gw.SetConfig(globalConf)
		}

		t.Run(env, func(t *testing.T) {
			t.Run("playground path is empty", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = ""
				g.Gw.LoadAPI(api)
				run(t, api.Proxy.ListenPath, api, env)
			})

			t.Run("playground path is '/'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/"
				g.Gw.LoadAPI(api)
				run(t, api.Proxy.ListenPath, api, env)
			})

			t.Run("playground path is '/playground'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/playground"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "playground"), api, env)
			})

			t.Run("playground path is '/ppp'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/ppp"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "/ppp"), api, env)
			})

			t.Run("playground path is '/zzz/'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/zzz/"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "/zzz"), api, env)
			})

			t.Run("playground path is 'aaa'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "aaa"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "aaa"), api, env)
			})

		})
	}
}

func TestCORS(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api1ID := uuid.New()
	api2ID := uuid.New()

	apis := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "CORS test API"
		spec.APIID = api1ID
		spec.Proxy.ListenPath = "/cors-api/"
		spec.CORS.Enable = false
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	}, func(spec *APISpec) {
		spec.Name = "Another API"
		spec.APIID = api2ID
		spec.Proxy.ListenPath = "/another-api/"
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	})

	headers := map[string]string{
		"Origin": "my-custom-origin",
	}

	headersMatch := map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Expose-Headers": "Custom-Header",
	}

	t.Run("CORS disabled", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("CORS enabled", func(t *testing.T) {
		apis[0].CORS.Enable = true
		g.Gw.LoadAPI(apis...)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusOK},
			{Path: "/another-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
			{Path: "/" + api1ID + "/", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusOK},
			{Path: "/" + api2ID + "/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("oauth endpoints", func(t *testing.T) {
		apis[0].UseOauth2 = true
		apis[0].CORS.Enable = false

		g.Gw.LoadAPI(apis...)

		t.Run("CORS disabled", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})

		t.Run("CORS enabled", func(t *testing.T) {
			apis[0].CORS.Enable = true
			g.Gw.LoadAPI(apis...)

			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})
	})
}

func TestTykRateLimitsStatusOfAPI(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const (
		quotaMax       = 20
		quotaRemaining = 10
		rate           = 10
		per            = 3
	)

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/my-api/"
		spec.UseKeylessAccess = false
	})
	_, key := g.CreateSession(func(s *user.SessionState) {
		s.QuotaMax = quotaMax
		s.QuotaRemaining = quotaRemaining
		s.Rate = rate
		s.Per = per

		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	authHeader := map[string]string{
		"Authorization": key,
	}

	bodyMatch := fmt.Sprintf(`{"quota":{"quota_max":%d,"quota_remaining":%d,"quota_renews":.*},"rate_limit":{"requests":%d,"per_unit":%d}}`,
		quotaMax, quotaRemaining, rate, per)

	_, _ = g.Run(t, test.TestCase{Path: "/my-api/tyk/rate-limits/", Headers: authHeader, BodyMatch: bodyMatch, Code: http.StatusOK})
}

func TestAllApisAreMTLS(t *testing.T) {
	// Create a new instance of the Gateway
	gw := &Gateway{
		apisByID: make(map[string]*APISpec),
	}

	// Define API specs
	spec1 := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			UseMutualTLSAuth: true,
			Active:           true,
			APIID:            "api1",
		},
	}
	spec2 := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			UseMutualTLSAuth: true,
			Active:           true,
			APIID:            "api2",
		},
	}
	spec3 := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			UseMutualTLSAuth: true,
			Active:           true,
			APIID:            "api3",
		},
	}

	// Add API specs to the gateway
	gw.apisByID[spec1.APIID] = spec1
	gw.apisByID[spec2.APIID] = spec2
	gw.apisByID[spec3.APIID] = spec3

	result := gw.allApisAreMTLS()

	expected := true
	if result != expected {
		t.Errorf("Expected AllApisAreMTLS to return %v, but got %v", expected, result)
	}

	// Change one API to not use mutual TLS authentication
	spec3.UseMutualTLSAuth = false

	// Call the method again
	result = gw.allApisAreMTLS()

	expected = false
	if result != expected {
		t.Errorf("Expected AllApisAreMTLS to return %v, but got %v", expected, result)
	}
}
<<<<<<< HEAD
=======

func TestOpenTelemetry(t *testing.T) {
	t.Run("Opentelemetry enabled - check if we are sending traces", func(t *testing.T) {
		otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
			//check the body
			body, err := io.ReadAll(r.Body)
			assert.Nil(t, err)

			assert.NotEmpty(t, body)

			// check the user agent
			agent, ok := r.Header["User-Agent"]
			assert.True(t, ok)
			assert.Len(t, agent, 1)
			assert.Contains(t, agent[0], "OTLP")

			//check if we are sending the traces to the right endpoint
			assert.Contains(t, r.URL.Path, "/v1/traces")

			// Here you can check the request and return a response
			w.WriteHeader(http.StatusOK)
		}, ":0")

		// Start the server.
		otelCollectorMock.Start()
		// Stop the server on return from the function.
		defer otelCollectorMock.Close()

		ts := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = true
			globalConf.OpenTelemetry.Exporter = "http"
			globalConf.OpenTelemetry.Endpoint = otelCollectorMock.URL
			globalConf.OpenTelemetry.SpanProcessorType = "simple"
		})
		defer ts.Close()
		detailedTracing := []bool{true, false}
		for _, detailed := range detailedTracing {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = "test"
				spec.Proxy.ListenPath = "/my-api/"
				spec.UseKeylessAccess = true
				spec.DetailedTracing = detailed
			})

			response, _ := ts.Run(t, test.TestCase{Path: "/my-api/", Code: http.StatusOK})
			assert.NotEmpty(t, response.Header.Get("X-Tyk-Trace-Id"))
			assert.Equal(t, "otel", ts.Gw.TracerProvider.Type())
		}

	})

	t.Run("Opentelemetry disabled - check if we are not sending traces", func(t *testing.T) {

		otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fail()
		}, ":0")

		// Start the server.
		otelCollectorMock.Start()
		// Stop the server on return from the function.
		defer otelCollectorMock.Close()

		ts := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = false
			globalConf.OpenTelemetry.Exporter = "http"
			globalConf.OpenTelemetry.Endpoint = otelCollectorMock.URL
			globalConf.OpenTelemetry.SpanProcessorType = "simple"
		})
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "test"
			spec.Proxy.ListenPath = "/my-api/"
			spec.UseKeylessAccess = true
		})

		response, _ := ts.Run(t, test.TestCase{Path: "/my-api/", Code: http.StatusOK})
		assert.Empty(t, response.Header.Get("X-Tyk-Trace-Id"))
		assert.Equal(t, "noop", ts.Gw.TracerProvider.Type())
	})
}

func httpCollectorMock(t *testing.T, fn http.HandlerFunc, address string) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("error setting up collector mock: %s", err.Error())
	}

	otelCollectorMock := httptest.NewUnstartedServer(fn)
	// NewUnstartedServer creates a listener. Close that listener and replace
	// with the one we created.
	otelCollectorMock.Listener.Close()
	otelCollectorMock.Listener = l

	return otelCollectorMock
}

func TestConfigureAuthAndOrgStores(t *testing.T) {

	testCases := []struct {
		name                 string
		storageEngine        apidef.StorageEngineCode
		expectedAuthStore    string
		expectedOrgStore     string
		expectedSessionStore string
		configureGateway     func(gw *Gateway)
	}{
		{
			name:                 "LDAP Storage Engine",
			storageEngine:        LDAPStorageEngine,
			expectedAuthStore:    "*gateway.LDAPStorageHandler",
			expectedOrgStore:     "*storage.RedisCluster",
			expectedSessionStore: "*storage.RedisCluster",
			configureGateway: func(gw *Gateway) {
			},
		}, {
			name:                 "RPC Storage engine",
			storageEngine:        RPCStorageEngine,
			expectedAuthStore:    "*gateway.RPCStorageHandler",
			expectedOrgStore:     "*storage.MdcbStorage",
			expectedSessionStore: "*gateway.RPCStorageHandler",
			configureGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.SlaveOptions.UseRPC = true
				gw.SetConfig(conf, true)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, context.Background())
			tc.configureGateway(gw)
			gs := gw.prepareStorage()

			spec := BuildAPI(func(spec *APISpec) {
				spec.AuthProvider.StorageEngine = tc.storageEngine

				if tc.storageEngine == RPCStorageEngine {
					spec.SessionProvider.StorageEngine = RPCStorageEngine
				}

				if tc.storageEngine == LDAPStorageEngine {
					// populate ldap meta
					meta := map[string]interface{}{
						"ldap_server":            "dummy-ldap-server",
						"ldap_port":              389.0,
						"base_dn":                "base-dn",
						"attributes":             []interface{}{"attr1", "attr2", "attr3"},
						"session_attribute_name": "attr-name",
						"search_string":          "the-search",
					}
					spec.AuthProvider.Meta = meta
				}
			})

			// Call configureAuthAndOrgStores
			authStore, orgStore, sessionStore := gw.configureAuthAndOrgStores(&gs, spec[0])

			if reflect.TypeOf(authStore).String() != tc.expectedAuthStore {
				t.Errorf("Expected authStore type %s, got %s", tc.expectedAuthStore, reflect.TypeOf(authStore).String())
			}
			if reflect.TypeOf(orgStore).String() != tc.expectedOrgStore {
				t.Errorf("Expected orgStore type %s, got %s", tc.expectedOrgStore, reflect.TypeOf(orgStore).String())
			}
			if reflect.TypeOf(sessionStore).String() != tc.expectedSessionStore {
				t.Errorf("Expected sessionStore type %s, got %s", tc.expectedSessionStore, reflect.TypeOf(sessionStore).String())
			}
		})
	}
}
>>>>>>> 76b4847da... TT-9158 prefetch org expiry when loading the apis (#5798)
