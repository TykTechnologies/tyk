package coprocess_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func TestBundleLoading(t *testing.T) {
	bundleID := "bundle.zip"

	t.Run("Signed bundle should load", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.PublicKeyPath = "testdata/server.pub"
			c.BundleBaseURL = "file://testdata/"
		})
		defer ts.Close()

		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.CustomMiddlewareBundle = bundleID
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/test/"
		})
		spec := specs[0]
		_ = spec

		//		bundle, err := ts.Gw.FetchBundle(spec)
		//		assert.NotNil(t, bundle)
		//		assert.NoError(t, err)

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusOK, BodyMatch: `New Request body`},
		}...)
	})

	t.Run("Invalid bundle signature should error", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.PublicKeyPath = "testdata/server-invalid.pub"
			c.BundleBaseURL = "file://testdata/"
		})
		defer ts.Close()

		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.CustomMiddlewareBundle = bundleID
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/test/"
		})
		spec := specs[0]
		_ = spec

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusNotFound},
		}...)
	})

	t.Run("Signed bundle but no public key should load bundle", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.PublicKeyPath = ""
			c.BundleBaseURL = "file://testdata/"
		})
		defer ts.Close()

		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.CustomMiddlewareBundle = bundleID
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/test/"
		})
		spec := specs[0]
		_ = spec

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusOK, BodyMatch: `New Request body`},
		}...)
	})

	t.Run("Full bundle from api spec should error", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.PublicKeyPath = "testdata/server.pub"
			c.BundleBaseURL = ""
		})
		defer ts.Close()

		specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
			spec.CustomMiddlewareBundle = "file://testdata/" + bundleID
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/test/"
		})
		spec := specs[0]
		_ = spec

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusNotFound},
		}...)
	})
}
