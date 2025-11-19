package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildServerRegenerationConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		conf             config.Config
		expectedProtocol string
		expectedHost     string
	}{
		{
			name: "HTTP with custom hostname and port",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					UseSSL: false,
				},
				HostName:   "api.example.com",
				ListenPort: 8080,
			},
			expectedProtocol: "http://",
			expectedHost:     "api.example.com:8080",
		},
		{
			name: "HTTPS with default port 443",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					UseSSL: true,
				},
				HostName:   "api.example.com",
				ListenPort: 443,
			},
			expectedProtocol: "https://",
			expectedHost:     "api.example.com", // No port for 443
		},
		{
			name: "HTTP with default port 80",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					UseSSL: false,
				},
				HostName:   "api.example.com",
				ListenPort: 80,
			},
			expectedProtocol: "http://",
			expectedHost:     "api.example.com", // No port for 80
		},
		{
			name: "fallback to listen address",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					UseSSL: false,
				},
				ListenAddress: "0.0.0.0",
				HostName:      "", // Empty hostname
				ListenPort:    8080,
			},
			expectedProtocol: "http://",
			expectedHost:     "0.0.0.0:8080",
		},
		{
			name: "fallback to default when both empty",
			conf: config.Config{
				HttpServerOptions: config.HttpServerOptionsConfig{
					UseSSL: false,
				},
				ListenAddress: "",
				HostName:      "",
				ListenPort:    8080,
			},
			expectedProtocol: "http://",
			expectedHost:     "127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := buildServerRegenerationConfig(tt.conf)

			assert.Equal(t, tt.expectedProtocol, result.Protocol)
			assert.Equal(t, tt.expectedHost, result.DefaultHost)
			assert.Nil(t, result.EdgeEndpoints, "Gateway should not have edge endpoints")
		})
	}
}

func TestExtractVersioningParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		baseAPIID           string
		versionName         string
		expectedBaseAPIID   string
		expectedVersionName string
	}{
		{
			name:                "versioned API parameters",
			baseAPIID:           "base-api-123",
			versionName:         "v2",
			expectedBaseAPIID:   "base-api-123",
			expectedVersionName: "v2",
		},
		{
			name:                "non-versioned API",
			baseAPIID:           "",
			versionName:         "",
			expectedBaseAPIID:   "",
			expectedVersionName: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := extractVersioningParams(tt.baseAPIID, tt.versionName)

			assert.Equal(t, tt.expectedBaseAPIID, result.BaseAPIID)
			assert.Equal(t, tt.expectedVersionName, result.VersionName)
		})
	}
}

func TestHandleOASServersForNewAPI(t *testing.T) {
	t.Parallel()

	t.Run("standalone API - no versioning", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		apiDef := &apidef.APIDefinition{
			APIID: "standalone-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		oasObj := &oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

		versionParams := versioningParams{} // Empty - not versioned

		err := gw.handleOASServersForNewAPI(apiDef, oasObj, versionParams)

		require.NoError(t, err)
		require.Len(t, oasObj.Servers, 1)
		assert.Equal(t, "http://localhost:8080/api", oasObj.Servers[0].URL)
	})

	t.Run("versioned child API with base API", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Base API with URL path versioning
		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Versions: map[string]string{
					"v1": "base-api",
					"v2": "child-api",
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		// Store base API in gateway's API map (required by getApiSpec)
		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
		}

		// Child API
		childAPIDef := &apidef.APIDefinition{
			APIID: "child-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2", // Own path, not used for versioned URL
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
			Internal: true, // Internal child
		}

		oasObj := &oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

		versionParams := versioningParams{
			BaseAPIID:   "base-api",
			VersionName: "v2",
		}

		err := gw.handleOASServersForNewAPI(childAPIDef, oasObj, versionParams)

		require.NoError(t, err)
		// Internal child should have only versioned URL
		require.Len(t, oasObj.Servers, 1)
		assert.Equal(t, "http://localhost:8080/products/v2", oasObj.Servers[0].URL)
	})

	t.Run("external versioned child API - gets both URLs", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Base API
		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Versions: map[string]string{
					"v2": "child-api",
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
		}

		// External child API
		childAPIDef := &apidef.APIDefinition{
			APIID: "child-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
			Internal: false, // External child
		}

		oasObj := &oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

		versionParams := versioningParams{
			BaseAPIID:   "base-api",
			VersionName: "v2",
		}

		err := gw.handleOASServersForNewAPI(childAPIDef, oasObj, versionParams)

		require.NoError(t, err)
		// External child should have both versioned + direct URLs
		require.Len(t, oasObj.Servers, 2)

		// Check both URLs are present
		urls := []string{oasObj.Servers[0].URL, oasObj.Servers[1].URL}
		assert.Contains(t, urls, "http://localhost:8080/products/v2") // Versioned
		assert.Contains(t, urls, "http://localhost:8080/products-v2") // Direct
	})
}

func TestHandleOASServersForUpdate(t *testing.T) {
	t.Parallel()

	t.Run("simple API update - preserves user servers", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Old API state
		oldAPIDef := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		oldSpec := &APISpec{
			APIDefinition: oldAPIDef,
		}

		// New API state with different listen path
		newAPIDef := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api/v2",
			},
		}

		// OAS with old Tyk server and user servers
		newOAS := &oas.OAS{
			T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/api"},  // Old Tyk server
					{URL: "https://api.example.com"},    // User server
					{URL: "https://backup.example.com"}, // User server
				},
			},
		}

		err := gw.handleOASServersForUpdate(oldSpec, newAPIDef, newOAS)

		require.NoError(t, err)
		// Should have 3 servers: 1 new Tyk + 2 user
		require.Len(t, newOAS.Servers, 3)

		// Old Tyk server should be gone
		for _, server := range newOAS.Servers {
			assert.NotEqual(t, "http://localhost:8080/api", server.URL)
		}

		// New Tyk server should be present
		urls := []string{newOAS.Servers[0].URL, newOAS.Servers[1].URL, newOAS.Servers[2].URL}
		assert.Contains(t, urls, "http://localhost:8080/api/v2")
		assert.Contains(t, urls, "https://api.example.com")
		assert.Contains(t, urls, "https://backup.example.com")
	})

	t.Run("base API update triggers cascade update", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Old base API state (URL path versioning)
		oldBaseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url", // URL path versioning
				Versions: map[string]string{
					"v1": "base-api",
					"v2": "child-api",
				},
			},
		}

		// Set IsOAS on the APIDefinition
		oldBaseAPIDef.IsOAS = true

		oldBaseSpec := &APISpec{
			APIDefinition: oldBaseAPIDef,
			OAS:           oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}},
		}

		// New base API state (changed to query param versioning)
		newBaseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url-param", // Changed from "url" to "url-param"
				Key:      "version",
				Versions: map[string]string{
					"v1": "base-api",
					"v2": "child-api",
				},
			},
		}

		// Child API
		childAPIDef := &apidef.APIDefinition{
			APIID: "child-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
			Internal: true,
		}

		// Set IsOAS on the APIDefinition
		childAPIDef.IsOAS = true

		childSpec := &APISpec{
			APIDefinition: childAPIDef,
			OAS: oas.OAS{T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/products/v2"}, // Old versioned URL
				},
			}},
		}

		// Store both APIs in gateway's API map (required by getApiSpec)
		gw.apisByID = map[string]*APISpec{
			"base-api":  oldBaseSpec,
			"child-api": childSpec,
		}

		newOAS := &oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

		err := gw.handleOASServersForUpdate(oldBaseSpec, newBaseAPIDef, newOAS)

		require.NoError(t, err)

		// Child API servers should have been updated
		// Old URL: http://localhost:8080/products/v2 (URL path versioning)
		// New URL: http://localhost:8080/products?version=v2 (query param versioning)
		hasNewVersionedURL := false
		for _, server := range childSpec.OAS.Servers {
			if server.URL == "http://localhost:8080/products?version=v2" {
				hasNewVersionedURL = true
			}
		}
		assert.True(t, hasNewVersionedURL, "Child API should have new query param versioned URL")
	})

	t.Run("non-base API update - no cascade", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Child API (not a base API)
		oldChildAPIDef := &apidef.APIDefinition{
			APIID: "child-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api", // This is a child, not a base
			},
		}

		// Set IsOAS on the APIDefinition
		oldChildAPIDef.IsOAS = true

		oldSpec := &APISpec{
			APIDefinition: oldChildAPIDef,
		}

		newChildAPIDef := &apidef.APIDefinition{
			APIID: "child-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2-updated",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
		}

		newOAS := &oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

		err := gw.handleOASServersForUpdate(oldSpec, newChildAPIDef, newOAS)

		require.NoError(t, err)
		// Should only update this API's servers, no cascade (verified by no panic/error)
	})
}

func TestUpdateOldDefaultChildServersGW(t *testing.T) {
	t.Parallel()

	t.Run("successfully updates old default child API servers", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		// Base API with URL path versioning - v2 is now the new default (changed from v1)
		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Location:          "url",
				Default:           "v2", // NEW default (was v1)
				FallbackToDefault: true, // Enable fallback URL for default version
				Versions: map[string]string{
					"v1": "child-v1",
					"v2": "child-v2",
				},
			},
		}
		baseAPIDef.IsOAS = true

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
			OAS:           oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}},
		}

		// Old default child API (v1) - should have its fallback URL removed
		oldDefaultChildAPIDef := &apidef.APIDefinition{
			APIID: "child-v1",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v1",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
			Internal: true,
		}
		oldDefaultChildAPIDef.IsOAS = true

		oldDefaultChildSpec := &APISpec{
			APIDefinition: oldDefaultChildAPIDef,
			OAS: oas.OAS{T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/products/v1"}, // Versioned URL
					{URL: "http://localhost:8080/products"},    // Fallback URL (should be removed)
				},
			}},
		}

		// Store APIs in gateway's API map
		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
			"child-v1": oldDefaultChildSpec,
		}

		// Use in-memory filesystem
		testFs := afero.NewMemMapFs()

		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)

		// Verify servers were regenerated
		// After the update, the old default child should have only its versioned URL,
		// without the fallback URL (since it's no longer the default)
		require.NotEmpty(t, oldDefaultChildSpec.OAS.Servers)

		// Collect all URLs for verification
		var urls []string
		for _, server := range oldDefaultChildSpec.OAS.Servers {
			urls = append(urls, server.URL)
		}

		// Should have the versioned URL
		assert.Contains(t, urls, "http://localhost:8080/products/v1", "Should have versioned URL")
		// Should NOT have the fallback URL anymore (since it's no longer the default)
		assert.NotContains(t, urls, "http://localhost:8080/products", "Should NOT have fallback URL")

		// Verify file was written (check it exists in the filesystem)
		// The exact path depends on writeToFile implementation, but we can verify no error occurred
	})

	t.Run("old default version not found in versions map", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Default:  "v2",
				Versions: map[string]string{
					"v2": "child-v2",
					// v1 not in map anymore (was deleted)
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
		}

		testFs := afero.NewMemMapFs()

		// Should not error - this is non-fatal
		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)
	})

	t.Run("old default is the base API itself - skips update", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Default:  "v2",
				Versions: map[string]string{
					"v1": "base-api", // Old default points to base API itself
					"v2": "child-v2",
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
		}

		testFs := afero.NewMemMapFs()

		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)
		// Should skip without error
	})

	t.Run("old default child API not found in loaded APIs", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Default:  "v2",
				Versions: map[string]string{
					"v1": "child-v1",
					"v2": "child-v2",
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		// child-v1 NOT in apisByID map (not loaded)
		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
		}

		testFs := afero.NewMemMapFs()

		// Should not error - this is non-fatal
		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)
	})

	t.Run("old default child is not OAS - skips update", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Default:  "v2",
				Versions: map[string]string{
					"v1": "child-v1",
					"v2": "child-v2",
				},
			},
		}

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
		}

		// Old default child is NOT OAS
		oldDefaultChildAPIDef := &apidef.APIDefinition{
			APIID: "child-v1",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v1",
			},
		}
		oldDefaultChildAPIDef.IsOAS = false // Not OAS

		oldDefaultChildSpec := &APISpec{
			APIDefinition: oldDefaultChildAPIDef,
		}

		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
			"child-v1": oldDefaultChildSpec,
		}

		testFs := afero.NewMemMapFs()

		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)
		// Should skip without error
	})

	t.Run("handles external child API correctly", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{}
		gw.SetConfig(config.Config{
			HttpServerOptions: config.HttpServerOptionsConfig{UseSSL: false},
			HostName:          "localhost",
			ListenPort:        8080,
		})

		baseAPIDef := &apidef.APIDefinition{
			APIID: "base-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Location:          "url",
				Default:           "v2",
				FallbackToDefault: true, // Enable fallback URL for default version
				Versions: map[string]string{
					"v1": "child-v1",
					"v2": "child-v2",
				},
			},
		}
		baseAPIDef.IsOAS = true

		baseAPISpec := &APISpec{
			APIDefinition: baseAPIDef,
			OAS:           oas.OAS{T: openapi3.T{Servers: openapi3.Servers{}}},
		}

		// External child API (Internal: false) - should update both versioned and direct URLs
		oldDefaultChildAPIDef := &apidef.APIDefinition{
			APIID: "child-v1",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v1",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api",
			},
			Internal: false, // External child
		}
		oldDefaultChildAPIDef.IsOAS = true

		oldDefaultChildSpec := &APISpec{
			APIDefinition: oldDefaultChildAPIDef,
			OAS: oas.OAS{T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/products/v1"}, // Versioned URL
					{URL: "http://localhost:8080/products"},    // Fallback URL (should be removed)
					{URL: "http://localhost:8080/products-v1"}, // Direct URL (should remain)
				},
			}},
		}

		gw.apisByID = map[string]*APISpec{
			"base-api": baseAPISpec,
			"child-v1": oldDefaultChildSpec,
		}

		testFs := afero.NewMemMapFs()

		err := gw.updateOldDefaultChildServersGW("v1", baseAPISpec, testFs)

		require.NoError(t, err)

		// Verify servers were regenerated
		require.NotEmpty(t, oldDefaultChildSpec.OAS.Servers)

		// Collect all URLs for verification
		var urls []string
		for _, server := range oldDefaultChildSpec.OAS.Servers {
			urls = append(urls, server.URL)
		}

		// External child should have versioned URL and direct URL
		assert.Contains(t, urls, "http://localhost:8080/products/v1", "Should have versioned URL")
		assert.Contains(t, urls, "http://localhost:8080/products-v1", "Should have direct URL")
		// Should NOT have the fallback URL anymore (since it's no longer the default)
		assert.NotContains(t, urls, "http://localhost:8080/products", "Should NOT have fallback URL")
	})
}
