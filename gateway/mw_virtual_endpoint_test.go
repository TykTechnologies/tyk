package gateway

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/assetloader"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const virtTestJS = `
function testVirtData(request, session, config) {
	var resp = {
		Body: "foobar",
		Headers: {
			"data-foo": config.config_data.foo,
			"data-bar-y": config.config_data.bar.y.toString(),
			"x-tyk-cache-action-set": "1",
			"x-tyk-cache-action-set-ttl": "10",
		},
		Code: 202
	}
	return TykJsResponse(resp, session.meta_data)
}
`

var (
	proxyOnErrorEnabled = true
	keylessAuthEnabled  = true
	cacheEnabled        = true

	proxyOnErrorDisabled = false
	keylessAuthDisabled  = false
	cacheDisabled        = false
)

func (ts *Test) testPrepareVirtualEndpoint(js, method, path string, proxyOnError, keyless, cacheEnabled, disabled bool) {
	ts.testPrepareVirtualEndpointWithDriver(js, method, path, proxyOnError, keyless, cacheEnabled, disabled, apidef.OttoDriver)
}

func (ts *Test) testPrepareVirtualEndpointWithDriver(js, method, path string, proxyOnError, keyless, cacheEnabled, disabled bool, driver apidef.MiddlewareDriver) {

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = keyless
		spec.Auth = apidef.AuthConfig{AuthHeaderName: "Authorization"}
		spec.CustomMiddleware.Driver = driver
		virtualMeta := apidef.VirtualMeta{
			Disabled:             disabled,
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   apidef.UseBlob,
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 path,
			Method:               method,
			ProxyOnError:         proxyOnError,
		}
		if !keyless {
			virtualMeta.UseSession = true
		}
		v := spec.VersionData.Versions["v1"]
		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			Virtual: []apidef.VirtualMeta{virtualMeta},
		}
		spec.VersionData.Versions["v1"] = v

		spec.ConfigData = map[string]interface{}{
			"foo": "x",
			"bar": map[string]interface{}{"y": 3},
		}

		// Address https://github.com/TykTechnologies/tyk/issues/1356
		// VP should work with cache enabled
		spec.CacheOptions = apidef.CacheOptions{
			EnableCache:                cacheEnabled,
			EnableUpstreamCacheControl: true,
			CacheTimeout:               60,
			CacheAllSafeRequests:       true,
		}
	})
}

func TestVirtualEndpoint(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			virtualPath := "/virt1-" + uuid.NewHex()
			ts.testPrepareVirtualEndpointWithDriver(virtTestJS, "GET", virtualPath,
				proxyOnErrorDisabled, keylessAuthEnabled, cacheEnabled, false, driver)

			_, _ = ts.Run(t,
				test.TestCase{
					Path:      virtualPath,
					Code:      202,
					BodyMatch: "foobar",
					HeadersNotMatch: map[string]string{
						cachedResponseHeader: "1",
					},
					HeadersMatch: map[string]string{
						"data-foo":   "x",
						"data-bar-y": "3",
					},
				},
				test.TestCase{
					Path:      virtualPath,
					Code:      202,
					BodyMatch: "foobar",
					HeadersMatch: map[string]string{
						"data-foo":           "x",
						"data-bar-y":         "3",
						cachedResponseHeader: "1",
					},
				},
			)
		})
	}
}

func TestVirtualEndpointNotCached(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			ts.testPrepareVirtualEndpointWithDriver(virtTestJS, "GET", "/virt",
				proxyOnErrorDisabled, keylessAuthEnabled, cacheDisabled, false, driver)

			_, _ = ts.Run(t,
				test.TestCase{
					Path:      "/virt",
					Code:      202,
					BodyMatch: "foobar",
					HeadersNotMatch: map[string]string{
						cachedResponseHeader: "1",
					},
					HeadersMatch: map[string]string{
						"data-foo":   "x",
						"data-bar-y": "3",
					},
				},
				test.TestCase{
					Path:      "/virt",
					Code:      202,
					BodyMatch: "foobar",
					HeadersNotMatch: map[string]string{
						cachedResponseHeader: "1",
					},
					HeadersMatch: map[string]string{
						"data-foo":   "x",
						"data-bar-y": "3",
					},
				},
			)
		})
	}
}

func TestVirtualEndpoint500(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			testErrorResponseWithDriver(ts, t, cacheEnabled, driver)
		})
	}
}

func TestVirtualEndpoint500NotCached(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			testErrorResponseWithDriver(ts, t, cacheDisabled, driver)
		})
	}
}

func testErrorResponseWithDriver(ts *Test, t *testing.T, cache bool, driver apidef.MiddlewareDriver) {
	ts.testPrepareVirtualEndpointWithDriver("abc", "GET", "/abc",
		proxyOnErrorDisabled, keylessAuthEnabled, cache, false, driver)

	_, _ = ts.Run(t,
		test.TestCase{
			Path: "/abc",
			Code: http.StatusInternalServerError,
			HeadersNotMatch: map[string]string{
				cachedResponseHeader: "1",
			},
		},
		test.TestCase{
			Path: "/abc",
			Code: http.StatusInternalServerError,
			HeadersNotMatch: map[string]string{
				cachedResponseHeader: "1",
			},
		},
	)
}

func TestVirtualEndpointSessionMetadata(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.AccessRights = map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}}
				s.MetaData = map[string]interface{}{
					"tyk_developer_id":       "5f11cc1ba4b16a176b4a6735",
					"tyk_key_request_fields": map[string]string{"key": "value"},
					"tyk_user_fields":        map[string]string{"key": "value"},
				}
			})

			ts.testPrepareVirtualEndpointWithDriver(virtTestJS, "GET", "/abc",
				proxyOnErrorDisabled, keylessAuthDisabled, cacheEnabled, false, driver)

			_, _ = ts.Run(t,
				test.TestCase{
					Path:    "/abc",
					Headers: map[string]string{"Authorization": key},
					Code:    http.StatusAccepted,
				},
				test.TestCase{
					Path:    "/abc",
					Headers: map[string]string{"Authorization": key},
					Code:    http.StatusAccepted,
				},
			)
		})
	}
}

func BenchmarkVirtualEndpoint(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	ts.testPrepareVirtualEndpoint(virtTestJS, "GET", "/virt",
		proxyOnErrorEnabled, keylessAuthEnabled, cacheEnabled, false)

	for i := 0; i < b.N; i++ {
		_, _ = ts.Run(b, test.TestCase{
			Path:      "/virt",
			Code:      202,
			BodyMatch: "foobar",
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		})
	}
}

func TestVirtualEndpointDisabled(t *testing.T) {
	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			ts.testPrepareVirtualEndpointWithDriver(virtTestJS, "GET", "/virt2",
				proxyOnErrorDisabled, keylessAuthEnabled, false, true, driver)

			_, _ = ts.Run(t,
				test.TestCase{
					Path:         "/virt2",
					BodyNotMatch: "foobar",
					HeadersNotMatch: map[string]string{
						"data-foo":   "x",
						"data-bar-y": "3",
					},
				},
			)
		})
	}
}

// ---------------------------------------------------------------------------
// preLoadVirtualMetaCodeGoja — unit tests for goja-specific loading branches
// ---------------------------------------------------------------------------

const simpleVirtJS = `
function simpleVirt(request, session, config) {
	var resp = { Body: "ok", Headers: {}, Code: 200 };
	return TykJsResponse(resp, session.meta_data);
}
`

func TestPreLoadVirtualMetaCodeGoja_UseFile(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Scripts are confined to middleware_path, so the file lives inside it.
	jsFile := filepath.Join(ts.Gw.GetConfig().MiddlewarePath, "virt-"+uuid.New()+".js")
	require.NoError(t, os.WriteFile(jsFile, []byte(simpleVirtJS), 0644))

	vm := &GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
	before := len(vm.programs)

	meta := &apidef.VirtualMeta{
		FunctionSourceType: apidef.UseFile,
		FunctionSourceURI:  jsFile,
	}

	ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)
	// The JS file should have been compiled and added as a program.
	assert.Greater(t, len(vm.programs), before)
}

func TestPreLoadVirtualMetaCodeGoja_UseFile_Missing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := &GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
	before := len(vm.programs)

	meta := &apidef.VirtualMeta{
		FunctionSourceType: apidef.UseFile,
		FunctionSourceURI:  filepath.Join(ts.Gw.GetConfig().MiddlewarePath, "nonexistent.js"),
	}

	ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)
	// File missing → no new program added.
	assert.Equal(t, before, len(vm.programs))
}

func TestPreLoadVirtualMetaCodeGoja_BlobDisabled(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.DisableVirtualPathBlobs = true
	})
	defer ts.Close()

	vm := &GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
	before := len(vm.programs)

	meta := &apidef.VirtualMeta{
		FunctionSourceType: apidef.UseBlob,
		FunctionSourceURI:  base64.StdEncoding.EncodeToString([]byte(simpleVirtJS)),
	}

	ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)
	// Blobs disabled → no new program added.
	assert.Equal(t, before, len(vm.programs))
}

func TestPreLoadVirtualMetaCodeGoja_UseBlob_InvalidBase64(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := &GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
	before := len(vm.programs)

	meta := &apidef.VirtualMeta{
		FunctionSourceType: apidef.UseBlob,
		FunctionSourceURI:  "!!!not-valid-base64!!!",
	}

	ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)
	// Invalid base64 → no new program added.
	assert.Equal(t, before, len(vm.programs))
}

func TestPreLoadVirtualMetaCodeGoja_UnknownType(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := &GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
	before := len(vm.programs)

	meta := &apidef.VirtualMeta{
		FunctionSourceType: "unknown-type",
		FunctionSourceURI:  "something",
	}

	ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)
	// Unknown type → no new program added.
	assert.Equal(t, before, len(vm.programs))
}

func TestPreLoadVirtualMetaCode_RejectsUnsafePath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.js")
	require.NoError(t, os.WriteFile(secret, []byte(simpleVirtJS), 0o644))

	// The rejection log must name the API but never the host path.
	assertSanitizedRejection := func(t *testing.T, hook *logrustest.Hook) {
		t.Helper()

		var rejected bool
		for _, e := range hook.AllEntries() {
			msg, err := e.String()
			require.NoError(t, err)
			assert.NotContains(t, msg, outside, "log entry leaks the host path")
			assert.NotContains(t, msg, "secret.js", "log entry leaks the host path")
			if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "Virtual endpoint script path rejected") {
				rejected = true
				assert.Equal(t, "test-api", e.Data["api_id"])
			}
		}
		assert.True(t, rejected, "expected a rejection warning")
	}

	meta := &apidef.VirtualMeta{
		ResponseFunctionName: "simpleVirt",
		FunctionSourceType:   apidef.UseFile,
		FunctionSourceURI:    secret,
	}

	t.Run("goja", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		vm := &GojaJSVM{}
		vm.Init(nil, logger.WithField("api_id", "test-api"), ts.Gw)
		before := len(vm.programs)

		ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)

		assert.Equal(t, before, len(vm.programs))
		assertSanitizedRejection(t, hook)
	})

	t.Run("otto", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		vm := &JSVM{}
		vm.Init(nil, logger.WithField("api_id", "test-api"), ts.Gw)

		ts.Gw.preLoadVirtualMetaCode(meta, vm)

		fn, err := vm.VM.Get("simpleVirt")
		require.NoError(t, err)
		assert.True(t, fn.IsUndefined(), "script outside middleware_path must not be loaded")
		assertSanitizedRejection(t, hook)
	})

	t.Run("flag on loads the script", func(t *testing.T) {
		origLoader := ts.Gw.JSAssetLoader
		defer func() { ts.Gw.JSAssetLoader = origLoader }()
		var err error
		ts.Gw.JSAssetLoader, err = assetloader.New(ts.Gw.GetConfig().MiddlewarePath, assetloader.WithAllowUnsafe(true))
		require.NoError(t, err)

		vm := &GojaJSVM{}
		vm.Init(nil, logrus.NewEntry(log), ts.Gw)
		before := len(vm.programs)

		ts.Gw.preLoadVirtualMetaCodeGoja(meta, vm)

		assert.Greater(t, len(vm.programs), before)
	})
}
