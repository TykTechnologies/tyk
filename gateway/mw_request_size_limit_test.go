package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	logrus "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestRequestSizeLimit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalSizeLimit = 1024
		})
	})[0]

	_, _ = ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/sample/", Data: strings.Repeat("a", 1024), Code: http.StatusOK},
		{Method: "POST", Path: "/sample/", Data: strings.Repeat("a", 1025), Code: http.StatusBadRequest},
	}...)

	t.Run("endpoint level", func(t *testing.T) {
		lim := apidef.RequestSizeMeta{Method: http.MethodPost, Path: "/get", SizeLimit: 512}

		UpdateAPIVersion(api, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			v.ExtendedPaths.SizeLimit = append(v.ExtendedPaths.SizeLimit, lim)
		})

		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPost, Path: "/sample/get", Data: strings.Repeat("a", 512), Code: http.StatusOK},
			{Method: http.MethodPost, Path: "/sample/get", Data: strings.Repeat("a", 513), Code: http.StatusBadRequest},
		}...)

		t.Run("disabled", func(t *testing.T) {
			UpdateAPIVersion(api, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.SizeLimit[0].Disabled = true
			})

			ts.Gw.LoadAPI(api)

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodPost, Path: "/sample/get", Data: strings.Repeat("a", 513), Code: http.StatusOK},
			}...)
		})
	})

	t.Run("should not break the request, if the method is skipped", func(t *testing.T) {
		// GET, DELETE, TRACE, OPTIONS and HEAD
		for method := range skippedMethods {
			_, _ = ts.Run(t, []test.TestCase{
				{Method: method, Path: "/sample/", Code: http.StatusOK},
			}...)
		}
	})

	t.Run("should break the request, if content-length is missing", func(t *testing.T) {
		// Golang's HTTP client automatically adds Content-Length to the request for POST, PUT and PATCH methods.
		logger, _ := logrus.NewNullLogger()
		spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.GlobalSizeLimit = 1024
			})
		})[0]
		baseMid := &BaseMiddleware{
			Spec:   spec,
			logger: logger.WithContext(context.Background()),
		}
		reqSizeLimitMiddleware := &RequestSizeLimitMiddleware{baseMid}

		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
			// Content-Length is missing in this request.
			body := bytes.NewBufferString(strings.Repeat("a", 3))
			r := httptest.NewRequest(method, "/sample", body)

			rw := httptest.NewRecorder()
			err, code := reqSizeLimitMiddleware.ProcessRequest(rw, r, nil)
			require.Equal(t, http.StatusLengthRequired, code)
			require.Errorf(t, err, "Content length is required for this request")
		}
	})

	t.Run("check enabled for spec", func(t *testing.T) {
		createMiddleware := func(versionInfoUpdater func(*apidef.VersionInfo)) *RequestSizeLimitMiddleware {
			logger, _ := logrus.NewNullLogger()
			spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				UpdateAPIVersion(spec, "v1", versionInfoUpdater)
			})[0]
			baseMid := &BaseMiddleware{
				Spec:   spec,
				logger: logger.WithContext(context.Background()),
			}
			return &RequestSizeLimitMiddleware{baseMid}
		}

		t.Run("request size limit set to 0 (disabled)", func(t *testing.T) {
			mw := createMiddleware(func(v *apidef.VersionInfo) {
				v.GlobalSizeLimit = 0
				v.GlobalSizeLimitDisabled = false
			})
			assert.False(t, mw.EnabledForSpec())
		})

		t.Run("request size limit set to value but disabled", func(t *testing.T) {
			mw := createMiddleware(func(v *apidef.VersionInfo) {
				v.GlobalSizeLimit = 5000
				v.GlobalSizeLimitDisabled = true
			})
			assert.False(t, mw.EnabledForSpec())
		})

		t.Run("request size limit set to 0 and disabled", func(t *testing.T) {
			mw := createMiddleware(func(v *apidef.VersionInfo) {
				v.GlobalSizeLimit = 0
				v.GlobalSizeLimitDisabled = true
			})
			assert.False(t, mw.EnabledForSpec())
		})

		t.Run("request size limit set to value and enabled", func(t *testing.T) {
			mw := createMiddleware(func(v *apidef.VersionInfo) {
				v.GlobalSizeLimit = 5000
				v.GlobalSizeLimitDisabled = false
			})
			assert.True(t, mw.EnabledForSpec())
		})
	})
}

func TestRequestSizeLimit_GlobalDisabledAtRequestTime(t *testing.T) {
	logger, _ := logrus.NewNullLogger()
	spec := BuildAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalSizeLimit = 1024
			v.GlobalSizeLimitDisabled = true
			v.UseExtendedPaths = true
			v.ExtendedPaths.SizeLimit = []apidef.RequestSizeMeta{
				{Method: http.MethodPost, Path: "/get", SizeLimit: 512},
			}
		})
	})[0]

	// Compile path matchers the same way the loader does for SizeLimit middleware.
	gw := &Gateway{}
	gw.SetConfig(config.Config{})
	loader := APIDefinitionLoader{Gw: gw}
	vInfo := spec.VersionData.Versions["v1"]
	urlSpecs := loader.compileRequestSizePathSpec(vInfo.ExtendedPaths.SizeLimit, RequestSizeLimit, config.Config{})
	spec.RxPaths = map[string][]URLSpec{"v1": urlSpecs}

	mw := &RequestSizeLimitMiddleware{BaseMiddleware: &BaseMiddleware{
		Spec:   spec,
		Gw:     gw,
		logger: logger.WithContext(context.Background()),
	}}

	body := bytes.NewBufferString(strings.Repeat("a", 2000))
	r := httptest.NewRequest(http.MethodPost, "/get", body)
	r.Header.Set("Content-Length", "2000")

	err, code := mw.ProcessRequest(httptest.NewRecorder(), r, nil)
	// Global limit is disabled, and /get path limit is 512 — path limit still applies.
	require.Error(t, err)
	require.Equal(t, http.StatusBadRequest, code)

	// Request under the path limit but over the (disabled) global limit must pass.
	bodyOK := bytes.NewBufferString(strings.Repeat("a", 500))
	rOK := httptest.NewRequest(http.MethodPost, "/get", bodyOK)
	rOK.Header.Set("Content-Length", "500")
	err, code = mw.ProcessRequest(httptest.NewRecorder(), rOK, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)

	// Unmatched path must not apply the disabled global limit.
	bodyGlobal := bytes.NewBufferString(strings.Repeat("a", 2000))
	rOther := httptest.NewRequest(http.MethodPost, "/other", bodyGlobal)
	rOther.Header.Set("Content-Length", "2000")
	err, code = mw.ProcessRequest(httptest.NewRecorder(), rOther, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
}
