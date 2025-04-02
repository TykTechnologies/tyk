package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	logrus "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
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
}
