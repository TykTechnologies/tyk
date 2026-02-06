package coprocess_test

import (
	"crypto/sha256"
	"hash"
	"net/http"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

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

		ts.Run(t, []test.TestCase{
			{Path: "/test/", Code: http.StatusOK, BodyMatch: `New Request body`},
		}...)

		t.Run("signed bundle should not verify checksum on reload", func(t *testing.T) {
			cfg := ts.Gw.GetConfig()
			cfg.SkipVerifyExistingPluginBundle = true
			ts.Gw.SetConfig(cfg)

			var conditionMet bool
			ts.Gw.BundleChecksumVerifier = func(_ *gateway.Bundle, _ afero.Fs, skipSignature, skipChecksum bool) (sha256Hash hash.Hash, err error) {
				conditionMet = !skipSignature && skipChecksum
				sha256Hash = sha256.New()
				return sha256Hash, nil
			}
			ts.Gw.DoReload()
			ts.Gw.LoadAPI(spec)
			assert.True(t, conditionMet)
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

func BenchmarkBundleLoading(b *testing.B) {
	bundleID := "bundle.zip"
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

	benchmarks := []struct {
		name         string
		skipVerify   bool
		hasPublicKey bool //setting this to false, simulates signature=false
	}{
		{
			name:         "skip verify=true hasSignature=true",
			skipVerify:   true,
			hasPublicKey: true,
		},
		{
			name:         "skip verify=false,hasSignature=true",
			skipVerify:   false,
			hasPublicKey: true,
		},
		{
			name:         "skip verify=false,hasSignature=false",
			skipVerify:   false,
			hasPublicKey: false,
		},
		{
			name:         "skip verify=true,hasSignature=false",
			skipVerify:   true,
			hasPublicKey: false,
		},
	}
	for _, bm := range benchmarks {
		cfg := ts.Gw.GetConfig()
		cfg.SkipVerifyExistingPluginBundle = bm.skipVerify
		if bm.hasPublicKey {
			cfg.PublicKeyPath = "testdata/server.pub"
		} else {
			cfg.PublicKeyPath = ""
		}
		ts.Gw.SetConfig(cfg)
		ts.Gw.DoReload()

		b.Run(bm.name, func(_ *testing.B) {
			ts.Gw.LoadAPI(spec)
		})
	}
}
