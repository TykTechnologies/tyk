package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/test"
	"github.com/TykTechnologies/tyk/v3/user"
	"github.com/go-redis/redis"
)

func TestURLRewrites(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths with url_rewrites", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
			{Path: "/reply/", Code: http.StatusOK, BodyMatch: "flump"},
			{Path: "/reply/123", Code: http.StatusOK, BodyMatch: "flump"},
			// Should get original upstream response
			{Path: "/get", Code: http.StatusOK, BodyMatch: `"Url":"/get"`},
			// Reject not whitelisted (but know by upstream) path
			{Method: "POST", Path: "/post", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/simple", "/regex/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should mock path
			{Path: "/simple", Code: http.StatusOK},
			{Path: "/regex/123/test", Code: http.StatusOK},
			{Path: "/regex/123/differ", Code: http.StatusForbidden},
			{Path: "/", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Test #1944", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/foo/{fooId}$", "/foo/{fooId}/bar/{barId}$", "/baz/{bazId}"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusForbidden},
			{Path: "/foo/", Code: http.StatusOK},
			{Path: "/foo/1", Code: http.StatusOK},
			{Path: "/foo/1/bar", Code: http.StatusForbidden},
			{Path: "/foo/1/bar/", Code: http.StatusOK},
			{Path: "/foo/1/bar/1", Code: http.StatusOK},
			{Path: "/", Code: http.StatusForbidden},
			{Path: "/baz", Code: http.StatusForbidden},
			{Path: "/baz/", Code: http.StatusOK},
			{Path: "/baz/1", Code: http.StatusOK},
			{Path: "/baz/1/", Code: http.StatusOK},
			{Path: "/baz/1/bazz", Code: http.StatusOK},
		}...)
	})

	t.Run("Case Sensitivity", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
}

func TestBlacklist(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
		BuildAndLoadAPI(func(spec *APISpec) {
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
		BuildAndLoadAPI(func(spec *APISpec) {
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
}

func TestConflictingPaths(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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
		{Method: "POST", Path: "/customer-servicing/documents/metadata/purge", Code: http.StatusOK},
		{Method: "GET", Path: "/customer-servicing/documents/metadata/{id}", Code: http.StatusOK},
	}...)
}

func TestIgnored(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
			{Method: "POST", Path: "/ext/ignored/literal", Code: 401},

			{Path: "/", Code: 401},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
			// All methods ignored
			{Method: "POST", Path: "/ext/ignored/literal", Code: http.StatusOK},

			{Path: "/", Code: 401},
		}...)
	})

	t.Run("With URL rewrite", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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

		LoadAPI(spec)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusUnauthorized},
			{Path: "/Foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusOK},
			{Path: "/Bar", Code: http.StatusOK},
		}...)

		t.Run("ignore-case globally", func(t *testing.T) {
			globalConf := config.Global()
			globalConf.IgnoreEndpointCase = true
			config.SetGlobal(globalConf)

			LoadAPI(spec)

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK},
				{Path: "/Foo", Code: http.StatusOK},
				{Path: "/bar", Code: http.StatusOK},
				{Path: "/Bar", Code: http.StatusOK},
			}...)
		})

		t.Run("ignore-case in api level", func(t *testing.T) {
			globalConf := config.Global()
			globalConf.IgnoreEndpointCase = false
			config.SetGlobal(globalConf)

			v := spec.VersionData.Versions["v1"]
			v.IgnoreEndpointCase = true
			spec.VersionData.Versions["v1"] = v

			LoadAPI(spec)

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK},
				{Path: "/Foo", Code: http.StatusOK},
				{Path: "/bar", Code: http.StatusOK},
				{Path: "/Bar", Code: http.StatusOK},
			}...)
		})

		// Check whether everything returns normal
		globalConf := config.Global()
		globalConf.IgnoreEndpointCase = false
		config.SetGlobal(globalConf)

		v := spec.VersionData.Versions["v1"]
		v.IgnoreEndpointCase = false
		spec.VersionData.Versions["v1"] = v

		LoadAPI(spec)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusUnauthorized},
			{Path: "/Foo", Code: http.StatusOK},
			{Path: "/bar", Code: http.StatusOK},
			{Path: "/Bar", Code: http.StatusOK},
		}...)
	})
}

func TestWhitelistMethodWithAdditionalMiddleware(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
			spec.ResponseProcessors = []apidef.ResponseProcessor{{Name: "header_injector"}}

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
	ReloadTestCase.Enable()
	defer ReloadTestCase.Disable()
	// Test Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer ts.Close()

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	globalConf := config.Global()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = ts.URL
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	var wg sync.WaitGroup
	wg.Add(1)
	msg := redis.Message{Payload: `{"Command": "ApiUpdated"}`}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(&msg, handled, wg.Done)

	ReloadTestCase.TickOk(t)

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("Should return array with one spec", apisByID)
	}
	apisMu.RUnlock()
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
	ts := StartTest()
	defer ts.Close()

	key := testPrepareDefaultVersion()

	authHeaders := map[string]string{"authorization": key}

	ts.Run(t, []test.TestCase{
		{Path: "/foo", Headers: authHeaders, Code: http.StatusForbidden},      // Not whitelisted for default v2
		{Path: "/bar", Headers: authHeaders, Code: http.StatusOK},             // Whitelisted for default v2
		{Path: "/foo?v=v1", Headers: authHeaders, Code: http.StatusOK},        // Allowed for v1
		{Path: "/bar?v=v1", Headers: authHeaders, Code: http.StatusForbidden}, // Not allowed for v1
	}...)
}

func BenchmarkDefaultVersion(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	key := testPrepareDefaultVersion()

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

func testPrepareDefaultVersion() string {
	BuildAndLoadAPI(func(spec *APISpec) {
		v1 := apidef.VersionInfo{Name: "v1"}
		v1.Name = "v1"
		v1.Paths.WhiteList = []string{"/foo"}

		v2 := apidef.VersionInfo{Name: "v2"}
		v2.Paths.WhiteList = []string{"/bar"}

		spec.VersionDefinition.Location = urlParamLocation
		spec.VersionDefinition.Key = "v"
		spec.VersionData.NotVersioned = false

		spec.VersionData.Versions["v1"] = v1
		spec.VersionData.Versions["v2"] = v2
		spec.VersionData.DefaultVersion = "v2"
		spec.Proxy.ListenPath = "/"

		spec.UseKeylessAccess = false
	})

	return CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "v2"},
		}}
	})
}

func TestGetVersionFromRequest(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	versionInfo := apidef.VersionInfo{}
	versionInfo.Paths.WhiteList = []string{"/foo"}
	versionInfo.Paths.BlackList = []string{"/bar"}

	t.Run("Header location", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = headerLocation
			spec.VersionDefinition.Key = "X-API-Version"
			spec.VersionData.Versions["v1"] = versionInfo
		})

		headers := map[string]string{"X-API-Version": "v1"}

		ts.Run(t, []test.TestCase{
			{Path: "/foo", Code: http.StatusOK, Headers: headers},
			{Path: "/bar", Code: http.StatusForbidden, Headers: headers},
		}...)
	})

	t.Run("URL param location", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = urlParamLocation
			spec.VersionDefinition.Key = "version"
			spec.VersionData.Versions["v2"] = versionInfo
		})

		ts.Run(t, []test.TestCase{
			{Path: "/foo?version=v2", Code: http.StatusOK},
			{Path: "/bar?version=v2", Code: http.StatusForbidden},
		}...)
	})

	t.Run("URL location", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = urlLocation
			spec.VersionData.Versions["v3"] = versionInfo
		})

		ts.Run(t, []test.TestCase{
			{Path: "/v3/foo", Code: http.StatusOK},
			{Path: "/v3/bar", Code: http.StatusForbidden},
		}...)
	})
}

func BenchmarkGetVersionFromRequest(b *testing.B) {
	b.ReportAllocs()
	ts := StartTest()
	defer ts.Close()

	versionInfo := apidef.VersionInfo{}
	versionInfo.Paths.WhiteList = []string{"/foo"}
	versionInfo.Paths.BlackList = []string{"/bar"}

	b.Run("Header location", func(b *testing.B) {
		b.ReportAllocs()
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = headerLocation
			spec.VersionDefinition.Key = "X-API-Version"
			spec.VersionData.Versions["v1"] = versionInfo
		})

		headers := map[string]string{"X-API-Version": "v1"}

		for i := 0; i < b.N; i++ {
			ts.Run(b, []test.TestCase{
				{Path: "/foo", Code: http.StatusOK, Headers: headers},
				{Path: "/bar", Code: http.StatusForbidden, Headers: headers},
			}...)
		}
	})

	b.Run("URL param location", func(b *testing.B) {
		b.ReportAllocs()
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = urlParamLocation
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
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.VersionData.NotVersioned = false
			spec.VersionDefinition.Location = urlLocation
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
	ReloadTestCase.Enable()
	defer ReloadTestCase.Disable()
	// Test Dashboard
	callNum := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer ts.Close()

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	globalConf := config.Global()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = ts.URL
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	var wg sync.WaitGroup
	wg.Add(1)
	msg := redis.Message{Payload: `{"Command": "ApiUpdated"}`}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(&msg, handled, wg.Done)

	ReloadTestCase.TickOk(t)

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("should return array with one spec", apisByID)
	}
	apisMu.RUnlock()

	// Second call

	var wg2 sync.WaitGroup
	wg2.Add(1)
	ReloadTestCase.Reset()
	handleRedisEvent(&msg, handled, wg2.Done)

	ReloadTestCase.TickOk(t)
	// Wait for the reload to finish, then check it worked
	wg2.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("second call should return array with one spec", apisByID)
	}
	apisMu.RUnlock()

}

func TestAPIDefinitionLoader_Template(t *testing.T) {
	const testTemplatePath = "../templates/transform_test.tmpl"

	l := APIDefinitionLoader{}

	executeAndAssert := func(t *testing.T, template *template.Template) {
		var bodyBuffer bytes.Buffer
		err := template.Execute(&bodyBuffer, map[string]string{
			"value1": "value-1",
			"value2": "value-2",
		})
		assert.NoError(t, err)

		var res map[string]string
		_ = json.Unmarshal(bodyBuffer.Bytes(), &res)

		assert.Equal(t, "value-1", res["value2"])
		assert.Equal(t, "value-2", res["value1"])
	}

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
