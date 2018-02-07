package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var (
	testBundlesPath = filepath.Join(testMiddlewarePath, "bundles")
)

var grpcBundleWithAuthCheck = map[string]string{
	"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "grpc",
		        "auth_check": {
		            "name": "MyAuthHook"
		        }
		    }
		}
	`,
}

func TestBundleLoader(t *testing.T) {
	bundleID := registerBundle("grpc_with_auth_check", grpcBundleWithAuthCheck)

	t.Run("Nonexistent bundle", func(t *testing.T) {
		specs := buildAndLoadAPI(func(spec *APISpec) {
			spec.CustomMiddlewareBundle = "nonexistent.zip"
		})
		err := loadBundle(specs[0])
		if err == nil {
			t.Fatal("Fetching a nonexistent bundle, expected an error")
		}
	})

	t.Run("Existing bundle with auth check", func(t *testing.T) {
		specs := buildAndLoadAPI(func(spec *APISpec) {
			spec.CustomMiddlewareBundle = bundleID
		})
		spec := specs[0]
		err := loadBundle(spec)
		if err != nil {
			t.Fatalf("Bundle not found: %s\n", bundleID)
		}

		bundleDir := fmt.Sprintf("%s-%s", spec.APIID, bundleID)
		savedBundlePath := filepath.Join(testBundlesPath, bundleDir)
		if _, err = os.Stat(savedBundlePath); os.IsNotExist(err) {
			t.Fatalf("Bundle wasn't saved to disk: %s", err.Error())
		}

		// Check bundle contents:
		if spec.CustomMiddleware.AuthCheck.Name != "MyAuthHook" {
			t.Fatalf("Auth check function doesn't match: got %s, expected %s\n", spec.CustomMiddleware.AuthCheck.Name, "MyAuthHook")
		}
		if string(spec.CustomMiddleware.Driver) != "grpc" {
			t.Fatalf("Driver doesn't match: got %s, expected %s\n", spec.CustomMiddleware.Driver, "grpc")
		}
	})
}
