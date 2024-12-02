package gateway

import (
	"net/http"
	"strings"
	"testing"

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

	t.Run("should not break the request if Content-Length is not present", func(t *testing.T) {
		methods := []string{
			http.MethodGet,
			http.MethodDelete,
			http.MethodConnect,
			http.MethodHead,
			http.MethodTrace,
			http.MethodOptions,
			http.MethodPut,
			http.MethodPost,
			http.MethodPatch,
		}
		for _, method := range methods {
			_, _ = ts.Run(t, []test.TestCase{
				{Method: method, Path: "/sample/", Code: http.StatusOK},
			}...)
		}
	})
}
