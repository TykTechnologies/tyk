package gateway

import (
	"crypto/md5"
	"fmt"
	"io"
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
	bundleID := RegisterBundle("grpc_with_auth_check", grpcBundleWithAuthCheck)

	t.Run("Nonexistent bundle", func(t *testing.T) {
		specs := BuildAndLoadAPI(func(spec *APISpec) {
			spec.CustomMiddlewareBundle = "nonexistent.zip"
		})
		err := loadBundle(specs[0])
		if err == nil {
			t.Fatal("Fetching a nonexistent bundle, expected an error")
		}
	})

	t.Run("Existing bundle with auth check", func(t *testing.T) {
		specs := BuildAndLoadAPI(func(spec *APISpec) {
			spec.CustomMiddlewareBundle = bundleID
		})
		spec := specs[0]
		err := loadBundle(spec)
		if err != nil {
			t.Fatalf("Bundle not found: %s\n", bundleID)
		}

		bundleNameHash := md5.New()
		io.WriteString(bundleNameHash, spec.CustomMiddlewareBundle)
		bundleDir := fmt.Sprintf("%s_%x", spec.APIID, bundleNameHash.Sum(nil))
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
