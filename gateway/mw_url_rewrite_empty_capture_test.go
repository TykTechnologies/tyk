package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

// TestURLRewrite_EmptyLeadingCaptureKeepsRemainingSegments covers a rewrite_to
// such as /$1/$2 where $1 is empty: the remaining segments stay in the path
// instead of being read as a host and dropped.
func TestURLRewrite_EmptyLeadingCaptureKeepsRemainingSegments(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/face2/"
		spec.Proxy.StripListenPath = true
		spec.UseKeylessAccess = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/e",
				Method:       http.MethodGet,
				MatchPattern: `^/face2/e\?a=([^&]*)&b=(.*)$`,
				RewriteTo:    "/$1/$2",
			}}
		})
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/face2/e?a=&b=segment",
		Code: http.StatusOK,
		BodyMatchFunc: func(body []byte) bool {
			assert.Equal(t, "/segment", upstreamPath(t, body))
			return true
		},
	})
}
