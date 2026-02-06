package coprocess_test

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"hash"
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

		t.Run("signed bundle should not verify checksum on reload", func(t *testing.T) {
			cfg := ts.Gw.GetConfig()
			cfg.SkipVerifyExistingPluginBundle = true
			ts.Gw.SetConfig(cfg)

			called := false
			ts.Gw.BundleChecksumVerifier = func(bundle *gateway.Bundle, bundleFs afero.Fs, useSignature bool) (sha256Hash hash.Hash, err error) {
				called = true
				return sha256Hash, nil
			}
			ts.Gw.DoReload()
			ts.Gw.LoadAPI(spec)
			assert.False(t, called)
		})
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
