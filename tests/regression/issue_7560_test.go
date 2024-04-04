package regression

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func Test_Issue7560(t *testing.T) {
	bundleID := "issue-7560-bundle.zip"

	ts := gateway.StartTest(func(c *config.Config) {
		c.PublicKeyPath = "testdata/issue-7560-server.pub"
		c.BundleBaseURL = "file://testdata/"
	})
	defer ts.Close()

	t.Run("Simple bundle base URL", func(t *testing.T) {
		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.CustomMiddlewareBundle = bundleID
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/test/"
		})
		spec := specs[0]

		bundle, err := ts.Gw.FetchBundle(spec)

		assert.NotNil(t, bundle)
		assert.NoError(t, err)

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusOK, BodyMatch: `New Request body`},
		}...)
	})
}
