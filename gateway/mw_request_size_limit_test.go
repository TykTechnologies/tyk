package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"net/http"
	"strings"
	"testing"
)

func TestRequestSizeLimitGlobalSizeLimit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalSizeLimit = 1024
		})
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/sample/", Data: strings.Repeat("a", 1024), Code: http.StatusOK},
		{Method: "POST", Path: "/sample/", Data: strings.Repeat("a", 1025), Code: http.StatusBadRequest},
	}...)
}
