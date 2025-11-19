package oas

import (
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		protocol   string
		host       string
		listenPath string
		expected   string
	}{
		{
			name:       "basic URL",
			protocol:   "http://",
			host:       "localhost:8080",
			listenPath: "/api",
			expected:   "http://localhost:8080/api",
		},
		{
			name:       "missing leading slash on path",
			protocol:   "https://",
			host:       "api.example.com",
			listenPath: "api",
			expected:   "https://api.example.com/api",
		},
		{
			name:       "trailing slash on host",
			protocol:   "http://",
			host:       "localhost:8080/",
			listenPath: "/api",
			expected:   "http://localhost:8080/api",
		},
		{
			name:       "double slash in path",
			protocol:   "http://",
			host:       "localhost:8080",
			listenPath: "/api//v1",
			expected:   "http://localhost:8080/api/v1",
		},
		{
			name:       "edge endpoint with protocol already included",
			protocol:   "http://",
			host:       "http://edge.example.com",
			listenPath: "/api",
			expected:   "http://edge.example.com/api",
		},
		{
			name:       "host with variables",
			protocol:   "https://",
			host:       "{subdomain}.example.com",
			listenPath: "/api",
			expected:   "https://{subdomain}.example.com/api",
		},
		{
			name:       "empty host returns relative path",
			protocol:   "http://",
			host:       "",
			listenPath: "/api",
			expected:   "/api",
		},
		{
			name:       "empty host with complex path",
			protocol:   "https://",
			host:       "",
			listenPath: "/api/v1/users",
			expected:   "/api/v1/users",
		},
		{
			name:       "empty host cleans double slashes",
			protocol:   "http://",
			host:       "",
			listenPath: "/api//v1",
			expected:   "/api/v1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := buildServerURL(tt.protocol, tt.host, tt.listenPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "trailing slash",
			input:    "http://localhost:8080/api/",
			expected: "http://localhost:8080/api",
		},
		{
			name:     "double slash",
			input:    "http://localhost:8080//api",
			expected: "http://localhost:8080/api",
		},
		{
			name:     "already normalized",
			input:    "http://localhost:8080/api",
			expected: "http://localhost:8080/api",
		},
		{
			name:     "with query params",
			input:    "http://localhost:8080/api?version=v1",
			expected: "http://localhost:8080/api?version=v1",
		},
		{
			name:     "root path",
			input:    "http://localhost:8080/",
			expected: "http://localhost:8080/",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizeServerURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildVersionedServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		protocol        string
		host            string
		listenPath      string
		versionLocation string
		versionKey      string
		versionName     string
		expectedURL     string
		expectedDesc    string
	}{
		{
			name:            "URL path versioning",
			protocol:        "http://",
			host:            "localhost:8080",
			listenPath:      "/api",
			versionLocation: "url",
			versionKey:      "",
			versionName:     "v2",
			expectedURL:     "http://localhost:8080/api/v2",
			expectedDesc:    "",
		},
		{
			name:            "query param versioning",
			protocol:        "http://",
			host:            "localhost:8080",
			listenPath:      "/api",
			versionLocation: "url-param",
			versionKey:      "version",
			versionName:     "v2",
			expectedURL:     "http://localhost:8080/api?version=v2",
			expectedDesc:    "",
		},
		{
			name:            "header versioning",
			protocol:        "http://",
			host:            "localhost:8080",
			listenPath:      "/api",
			versionLocation: "header",
			versionKey:      "X-API-Version",
			versionName:     "v2",
			expectedURL:     "http://localhost:8080/api",
			expectedDesc:    "",
		},
		{
			name:            "unknown location defaults to URL",
			protocol:        "http://",
			host:            "localhost:8080",
			listenPath:      "/api",
			versionLocation: "unknown",
			versionKey:      "",
			versionName:     "v2",
			expectedURL:     "http://localhost:8080/api/v2",
			expectedDesc:    "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url, desc := buildVersionedServerURL(
				tt.protocol, tt.host, tt.listenPath,
				tt.versionLocation, tt.versionKey, tt.versionName,
			)
			assert.Equal(t, tt.expectedURL, url)
			assert.Equal(t, tt.expectedDesc, desc)
		})
	}
}

func TestDetermineHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apiData  *apidef.APIDefinition
		config   ServerRegenerationConfig
		expected []string
	}{
		{
			name: "custom domain takes precedence",
			apiData: &apidef.APIDefinition{
				Domain: "api.example.com",
				Tags:   []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost: "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{"api.example.com"},
		},
		{
			name: "edge endpoints when no custom domain",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost: "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod", "backup"}},
				},
			},
			expected: []string{"http://edge1.example.com", "http://edge2.example.com", ""},
		},
		{
			name:    "default host when no custom domain or edge endpoints",
			apiData: &apidef.APIDefinition{},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{},
			},
			expected: []string{"localhost:8080", ""},
		},
		{
			name: "edge endpoints but no matching tags → relative paths",
			apiData: &apidef.APIDefinition{
				Tags: []string{"dev"},
			},
			config: ServerRegenerationConfig{
				DefaultHost: "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := determineHosts(tt.apiData, tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRemoveTykGeneratedURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		servers      openapi3.Servers
		tykURLs      []string
		expectedLen  int
		shouldRemain []string
	}{
		{
			name: "remove Tyk URLs from mixed servers",
			servers: openapi3.Servers{
				{URL: "http://localhost:8080/api"},
				{URL: "https://api.example.com"},
				{URL: "http://localhost:8080/api/v2"},
				{URL: "https://backup.example.com"},
			},
			tykURLs: []string{
				"http://localhost:8080/api",
				"http://localhost:8080/api/v2",
			},
			expectedLen:  2,
			shouldRemain: []string{"https://api.example.com", "https://backup.example.com"},
		},
		{
			name: "remove all if all are Tyk URLs",
			servers: openapi3.Servers{
				{URL: "http://localhost:8080/api"},
				{URL: "http://localhost:8080/api/v2"},
			},
			tykURLs: []string{
				"http://localhost:8080/api",
				"http://localhost:8080/api/v2",
			},
			expectedLen:  0,
			shouldRemain: []string{},
		},
		{
			name: "keep all if no Tyk URLs tracked",
			servers: openapi3.Servers{
				{URL: "https://api.example.com"},
				{URL: "https://backup.example.com"},
			},
			tykURLs:      []string{},
			expectedLen:  2,
			shouldRemain: []string{"https://api.example.com", "https://backup.example.com"},
		},
		{
			name: "handles URL normalization with trailing slash",
			servers: openapi3.Servers{
				{URL: "http://localhost:8080/api/"},
				{URL: "https://api.example.com"},
			},
			tykURLs:      []string{"http://localhost:8080/api"}, // No trailing slash
			expectedLen:  1,
			shouldRemain: []string{"https://api.example.com"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := removeTykGeneratedURLs(tt.servers, tt.tykURLs)
			assert.Equal(t, tt.expectedLen, len(result))

			// Verify expected URLs are present
			for _, expectedURL := range tt.shouldRemain {
				found := false
				for _, server := range result {
					if server.URL == expectedURL {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected URL %s not found in result", expectedURL)
			}
		})
	}
}

func TestGenerateStandardServers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		apiData       *apidef.APIDefinition
		config        ServerRegenerationConfig
		expectedCount int
		expectedURLs  []string
	}{
		{
			name: "single default host",
			apiData: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expectedCount: 2,
			expectedURLs:  []string{"http://localhost:8080/api", "/api"},
		},
		{
			name: "custom domain",
			apiData: &apidef.APIDefinition{
				Domain: "api.example.com",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "https://",
				DefaultHost: "localhost:8080",
			},
			expectedCount: 1,
			expectedURLs:  []string{"https://api.example.com/products"},
		},
		{
			name: "multiple edge endpoints",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod"}},
				},
			},
			expectedCount: 3,
			expectedURLs:  []string{"http://edge1.example.com/api", "http://edge2.example.com/api", "/api"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := generateStandardServers(tt.apiData, tt.config)
			assert.Equal(t, tt.expectedCount, len(result))

			for _, expectedURL := range tt.expectedURLs {
				found := false
				for _, server := range result {
					if server.url == expectedURL {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected URL %s not found", expectedURL)
			}
		})
	}
}

func TestGenerateVersionedServers(t *testing.T) {
	t.Parallel()

	t.Run("child API with URL path versioning", func(t *testing.T) {
		t.Parallel()

		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Versions: map[string]string{
					"v1": "base-id",
					"v2": "child-id",
				},
			},
		}

		childAPI := &apidef.APIDefinition{
			APIID: "child-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-id",
			},
			Internal: false, // External
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := generateVersionedServers(childAPI, baseAPI, config, "v2")

		// External child should have 2 URLs: versioned + direct
		assert.Equal(t, 2, len(servers))

		// Check versioned URL
		hasVersioned := false
		for _, s := range servers {
			if s.url == "http://localhost:8080/products/v2" {
				hasVersioned = true
			}
		}
		assert.True(t, hasVersioned, "Should have versioned URL")

		// Check direct URL
		hasDirect := false
		for _, s := range servers {
			if s.url == "http://localhost:8080/products-v2" {
				hasDirect = true
			}
		}
		assert.True(t, hasDirect, "Should have direct URL")
	})

	t.Run("child API with query param versioning", func(t *testing.T) {
		t.Parallel()

		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url-param",
				Key:      "version",
				Versions: map[string]string{
					"v2": "child-id",
				},
			},
		}

		childAPI := &apidef.APIDefinition{
			APIID: "child-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-id",
			},
			Internal: false,
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := generateVersionedServers(childAPI, baseAPI, config, "v2")

		hasVersioned := false
		for _, s := range servers {
			if s.url == "http://localhost:8080/products?version=v2" {
				hasVersioned = true
			}
		}
		assert.True(t, hasVersioned, "Should have query param versioned URL")
	})

	t.Run("internal child API gets only versioned URL", func(t *testing.T) {
		t.Parallel()

		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Versions: map[string]string{
					"v2": "child-id",
				},
			},
		}

		childAPI := &apidef.APIDefinition{
			APIID: "child-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-id",
			},
			Internal: true, // Internal
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := generateVersionedServers(childAPI, baseAPI, config, "v2")

		// Internal child should have only 1 URL: versioned
		assert.Equal(t, 1, len(servers))
		assert.Equal(t, "http://localhost:8080/products/v2", servers[0].url)
	})
}

func TestRegenerateServers(t *testing.T) {
	t.Parallel()

	t.Run("state transition preserves user servers", func(t *testing.T) {
		t.Parallel()

		// Old state: API at /api
		oldAPI := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		// New state: API at /api/v2
		newAPI := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api/v2",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		// OAS with old Tyk URL and user servers
		oas := &OAS{
			T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/api"},
					{URL: "https://api.example.com"},
					{URL: "https://backup.example.com"},
				},
			},
		}

		err := oas.RegenerateServers(newAPI, oldAPI, nil, nil, config, "")
		require.NoError(t, err)

		// Should have 4 servers: 2 new Tyk (absolute + relative) + 2 user
		assert.Equal(t, 4, len(oas.Servers))

		// Old Tyk URL should be gone
		for _, server := range oas.Servers {
			assert.NotEqual(t, "http://localhost:8080/api", server.URL)
		}

		// New Tyk URL should be present
		foundNewTyk := false
		for _, server := range oas.Servers {
			if strings.Contains(server.URL, "/api/v2") {
				foundNewTyk = true
			}
		}
		assert.True(t, foundNewTyk)

		// User servers should be present
		foundUser1 := false
		foundUser2 := false
		for _, server := range oas.Servers {
			if server.URL == "https://api.example.com" {
				foundUser1 = true
			}
			if server.URL == "https://backup.example.com" {
				foundUser2 = true
			}
		}
		assert.True(t, foundUser1)
		assert.True(t, foundUser2)
	})

	t.Run("import scenario with no old state", func(t *testing.T) {
		t.Parallel()

		newAPI := &apidef.APIDefinition{
			APIID: "imported-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/petstore",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		// OAS with user-provided servers (from import)
		oas := &OAS{
			T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "https://api.example.com"},
					{URL: "https://staging.example.com"},
				},
			},
		}

		err := oas.RegenerateServers(newAPI, nil, nil, nil, config, "")
		require.NoError(t, err)

		// Should have 4 servers: 2 Tyk (absolute + relative) + 2 user
		assert.Equal(t, 4, len(oas.Servers))

		// Tyk URL should be present
		foundTyk := false
		for _, server := range oas.Servers {
			if strings.Contains(server.URL, "/petstore") && strings.Contains(server.URL, "localhost") {
				foundTyk = true
			}
		}
		assert.True(t, foundTyk)
	})

	t.Run("deduplication with matching URLs", func(t *testing.T) {
		t.Parallel()

		newAPI := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		// User server matches what Tyk will generate
		oas := &OAS{
			T: openapi3.T{
				Servers: openapi3.Servers{
					{URL: "http://localhost:8080/api"},
				},
			},
		}

		err := oas.RegenerateServers(newAPI, nil, nil, nil, config, "")
		require.NoError(t, err)

		// Should have 2 servers: absolute URL (deduplicated) + relative path
		assert.Equal(t, 2, len(oas.Servers))
		assert.Equal(t, "http://localhost:8080/api", oas.Servers[0].URL)
		assert.Equal(t, "/api", oas.Servers[1].URL)
	})
}

func TestGenerateTykServersBaseAPIWithVersioning(t *testing.T) {
	t.Parallel()

	t.Run("base API with versioning gets versioned URL only", func(t *testing.T) {
		t.Parallel()

		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Name:     "v1",
				Location: "url",
				Versions: map[string]string{
					"v1": "base-id",
					"v2": "child-id",
				},
			},
			Internal: false,
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := generateTykServers(baseAPI, nil, config, "")

		// Base API should have only versioned URL (no direct access)
		assert.Equal(t, 1, len(servers))
		assert.Equal(t, "http://localhost:8080/products/v1", servers[0].url)
	})
}

func TestOAS_GenerateTykServers(t *testing.T) {
	t.Parallel()

	t.Run("standard non-versioned API", func(t *testing.T) {
		t.Parallel()

		oas := &OAS{}
		apiDef := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/test",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := oas.GenerateTykServers(apiDef, nil, config, "")

		require.Len(t, servers, 1)
		assert.Equal(t, "http://localhost:8080/test", servers[0].URL)
	})

	t.Run("versioned child API with URL path versioning", func(t *testing.T) {
		t.Parallel()

		oas := &OAS{}
		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  true,
				Location: "url",
				Key:      "version",
				Versions: map[string]string{
					"v1": "base-id",
					"v2": "child-id",
				},
			},
		}

		childAPI := &apidef.APIDefinition{
			APIID: "child-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionData: apidef.VersionData{
				NotVersioned: false,
				Versions: map[string]apidef.VersionInfo{
					"v2": {},
				},
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "https://",
			DefaultHost: "api.example.com",
		}

		servers := oas.GenerateTykServers(childAPI, baseAPI, config, "v2")

		// Should have versioned URL
		require.NotEmpty(t, servers)
		found := false
		for _, server := range servers {
			if server.URL == "https://api.example.com/products/v2" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected to find versioned URL https://api.example.com/products/v2")
	})

	t.Run("API with custom domain", func(t *testing.T) {
		t.Parallel()

		oas := &OAS{}
		apiDef := &apidef.APIDefinition{
			APIID:  "test-api",
			Domain: "custom.example.com",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "https://",
			DefaultHost: "localhost:8080",
		}

		servers := oas.GenerateTykServers(apiDef, nil, config, "")

		require.Len(t, servers, 1)
		assert.Equal(t, "https://custom.example.com/api", servers[0].URL)
	})

	t.Run("base API with versioning and fallback", func(t *testing.T) {
		t.Parallel()

		oas := &OAS{}
		baseAPI := &apidef.APIDefinition{
			APIID: "base-id",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Location:          "url",
				Default:           "v1",
				FallbackToDefault: true,
				Versions: map[string]string{
					"v1": "base-id",
				},
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := oas.GenerateTykServers(baseAPI, nil, config, "")

		// Should have both versioned URL and fallback URL
		require.Len(t, servers, 2)
		urls := []string{servers[0].URL, servers[1].URL}
		assert.Contains(t, urls, "http://localhost:8080/products/v1")
		assert.Contains(t, urls, "http://localhost:8080/products")
	})

	t.Run("returns openapi3.Server type not serverInfo", func(t *testing.T) {
		t.Parallel()

		oas := &OAS{}
		apiDef := &apidef.APIDefinition{
			APIID: "test-api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/test",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		servers := oas.GenerateTykServers(apiDef, nil, config, "")

		// Verify it returns the correct type
		require.NotNil(t, servers)
		require.IsType(t, []*openapi3.Server{}, servers)
		require.Len(t, servers, 1)
		require.IsType(t, &openapi3.Server{}, servers[0])
	})
}

func TestShouldUpdateChildAPIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		newAPI   *apidef.APIDefinition
		oldAPI   *apidef.APIDefinition
		expected bool
	}{
		{
			name: "versioning method changed - should update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url-param",
					Key:      "version",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: true,
		},
		{
			name: "versioning key changed - should update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url-param",
					Key:      "api-version",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url-param",
					Key:      "version",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: true,
		},
		{
			name: "listen path changed - should update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api/v2/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: true,
		},
		{
			name: "no relevant changes - should not update",
			newAPI: &apidef.APIDefinition{
				APIID:  "base-id",
				Domain: "api.example.com", // Custom domain changed - doesn't affect children
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Key:      "version",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID:  "base-id",
				Domain: "old.example.com",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Key:      "version",
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: false,
		},
		{
			name: "not a base API - should not update",
			newAPI: &apidef.APIDefinition{
				APIID: "child-id",
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-id", // This is a child API
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "child-id",
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-id",
				},
			},
			expected: false,
		},
		{
			name: "old API is nil - should not update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Versions: map[string]string{
						"v1": "base-id",
					},
				},
			},
			oldAPI:   nil,
			expected: false,
		},
		{
			name: "fallbackToDefault changed - should update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					BaseID:            "base-id",
					Location:          "url",
					Default:           "v1",
					FallbackToDefault: true, // Changed to true
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					BaseID:            "base-id",
					Location:          "url",
					Default:           "v1",
					FallbackToDefault: false, // Was false
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: true,
		},
		{
			name: "default version changed - should update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					BaseID:            "base-id",
					Location:          "url",
					Default:           "v2", // Changed to v2
					FallbackToDefault: true,
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					BaseID:            "base-id",
					Location:          "url",
					Default:           "v1", // Was v1
					FallbackToDefault: true,
					Versions: map[string]string{
						"v1": "base-id",
						"v2": "child-id",
					},
				},
			},
			expected: true,
		},
		{
			name: "no versions defined - should not update",
			newAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url",
					Versions: map[string]string{}, // Empty versions
				},
			},
			oldAPI: &apidef.APIDefinition{
				APIID: "base-id",
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					BaseID:   "base-id",
					Location: "url-param",
					Versions: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name:     "new API is nil - should not update",
			newAPI:   nil,
			oldAPI:   &apidef.APIDefinition{APIID: "base-id"},
			expected: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ShouldUpdateChildAPIs(tt.newAPI, tt.oldAPI)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractUserServers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		existingServers openapi3.Servers
		apiDef          *apidef.APIDefinition
		baseAPI         *apidef.APIDefinition
		config          ServerRegenerationConfig
		versionName     string
		expected        []string // Expected user server URLs
		description     string
	}{
		{
			name:            "empty servers returns empty",
			existingServers: openapi3.Servers{},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{},
			description: "Empty input should return empty output",
		},
		{
			name: "filters out single Tyk server, keeps user server",
			existingServers: openapi3.Servers{
				{URL: "http://localhost:8080/api"},        // Tyk server
				{URL: "https://api.example.com/external"}, // User server
			},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{"https://api.example.com/external"},
			description: "Should filter out Tyk server and keep user server",
		},
		{
			name: "filters out multiple Tyk servers (edge endpoints)",
			existingServers: openapi3.Servers{
				{URL: "http://edge1.example.com/api"}, // Tyk edge 1
				{URL: "http://edge2.example.com/api"}, // Tyk edge 2
				{URL: "https://custom.com/api"},       // User server
				{URL: "https://backup.com/api"},       // User server
			},
			apiDef: &apidef.APIDefinition{
				Tags: []string{"prod"},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod"}},
				},
			},
			expected:    []string{"https://custom.com/api", "https://backup.com/api"},
			description: "Should filter out multiple Tyk edge servers and keep user servers",
		},
		{
			name: "all servers are Tyk-generated",
			existingServers: openapi3.Servers{
				{URL: "http://localhost:8080/api"},
			},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{},
			description: "Should return empty when all servers are Tyk-generated",
		},
		{
			name: "all servers are user-provided",
			existingServers: openapi3.Servers{
				{URL: "https://api.example.com/v1"},
				{URL: "https://api.example.com/v2"},
				{URL: "https://backup.example.com/api"},
			},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{"https://api.example.com/v1", "https://api.example.com/v2", "https://backup.example.com/api"},
			description: "Should return all servers when none are Tyk-generated",
		},
		{
			name: "handles custom domain Tyk server",
			existingServers: openapi3.Servers{
				{URL: "https://api.custom.com/products"}, // Tyk with custom domain
				{URL: "https://user-server.com/api"},     // User server
			},
			apiDef: &apidef.APIDefinition{
				Domain: "api.custom.com",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "https://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{"https://user-server.com/api"},
			description: "Should filter out Tyk server with custom domain",
		},
		{
			name: "handles versioned child API with both versioned and direct URLs",
			existingServers: openapi3.Servers{
				{URL: "http://localhost:8080/products/v2"}, // Tyk versioned URL
				{URL: "http://localhost:8080/products-v2"}, // Tyk direct URL
				{URL: "https://external.com/api"},          // User server
			},
			apiDef: &apidef.APIDefinition{
				APIID: "child-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products-v2",
				},
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-id",
				},
				Internal: false,
			},
			baseAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					Location: "url",
					Versions: map[string]string{
						"v2": "child-id",
					},
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			versionName: "v2",
			expected:    []string{"https://external.com/api"},
			description: "Should filter out both versioned and direct Tyk URLs for child API",
		},
		{
			name: "handles URL normalization with trailing slashes",
			existingServers: openapi3.Servers{
				{URL: "http://localhost:8080/api/"}, // Tyk server with trailing slash
				{URL: "https://user.com/api"},       // User server
				{URL: "https://backup.com/api/"},    // User server with trailing slash
			},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{"https://user.com/api", "https://backup.com/api/"},
			description: "Should handle trailing slashes correctly via normalization",
		},
		{
			name: "server order doesn't matter",
			existingServers: openapi3.Servers{
				{URL: "https://user1.com/api"},     // User server first
				{URL: "http://localhost:8080/api"}, // Tyk server in middle
				{URL: "https://user2.com/api"},     // User server last
			},
			apiDef: &apidef.APIDefinition{
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			expected:    []string{"https://user1.com/api", "https://user2.com/api"},
			description: "Should work regardless of server order in array",
		},
		{
			name: "handles query param versioning",
			existingServers: openapi3.Servers{
				{URL: "http://localhost:8080/products?version=v2"}, // Tyk with query param
				{URL: "https://external.com/api"},                  // User server
			},
			apiDef: &apidef.APIDefinition{
				APIID: "child-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-id",
				},
			},
			baseAPI: &apidef.APIDefinition{
				APIID: "base-id",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:  true,
					Location: "url-param",
					Key:      "version",
					Versions: map[string]string{
						"v2": "child-id",
					},
				},
			},
			config: ServerRegenerationConfig{
				Protocol:    "http://",
				DefaultHost: "localhost:8080",
			},
			versionName: "v2",
			expected:    []string{"https://external.com/api"},
			description: "Should handle query parameter versioning",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ExtractUserServers(
				tt.existingServers,
				tt.apiDef,
				tt.baseAPI,
				tt.config,
				tt.versionName,
			)
			require.NoError(t, err)

			// Check that we got the expected number of user servers
			assert.Equal(t, len(tt.expected), len(result), tt.description)

			// Check that each expected URL is present
			for _, expectedURL := range tt.expected {
				found := false
				for _, server := range result {
					if server.URL == expectedURL {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected user server URL %s not found. Description: %s", expectedURL, tt.description)
			}

			// Verify no Tyk servers leaked through
			if len(tt.expected) > 0 {
				// Regenerate Tyk servers to verify they're not in the result
				tempOAS := &OAS{T: openapi3.T{Servers: openapi3.Servers{}}}
				err := tempOAS.RegenerateServers(tt.apiDef, nil, tt.baseAPI, nil, tt.config, tt.versionName)
				require.NoError(t, err)

				for _, tykServer := range tempOAS.Servers {
					tykNormalized := normalizeServerURL(tykServer.URL)
					for _, userServer := range result {
						userNormalized := normalizeServerURL(userServer.URL)
						assert.NotEqual(t, tykNormalized, userNormalized,
							"Tyk server %s should not be in user servers. Description: %s",
							tykServer.URL, tt.description)
					}
				}
			}
		})
	}
}

func TestExtractUserServers_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("preserves server order of user servers", func(t *testing.T) {
		t.Parallel()

		existingServers := openapi3.Servers{
			{URL: "https://primary.com/api"},
			{URL: "http://localhost:8080/api"}, // Tyk server
			{URL: "https://secondary.com/api"},
			{URL: "https://tertiary.com/api"},
		}

		apiDef := &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		result, err := ExtractUserServers(existingServers, apiDef, nil, config, "")
		require.NoError(t, err)

		require.Equal(t, 3, len(result))
		assert.Equal(t, "https://primary.com/api", result[0].URL)
		assert.Equal(t, "https://secondary.com/api", result[1].URL)
		assert.Equal(t, "https://tertiary.com/api", result[2].URL)
	})

	t.Run("handles APIs with no base API gracefully", func(t *testing.T) {
		t.Parallel()

		existingServers := openapi3.Servers{
			{URL: "http://localhost:8080/api"},
			{URL: "https://user.com/api"},
		}

		apiDef := &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		// baseAPI is nil - should still work for non-versioned APIs
		result, err := ExtractUserServers(existingServers, apiDef, nil, config, "")
		require.NoError(t, err)

		require.Equal(t, 1, len(result))
		assert.Equal(t, "https://user.com/api", result[0].URL)
	})

	t.Run("handles empty version name for non-versioned APIs", func(t *testing.T) {
		t.Parallel()

		existingServers := openapi3.Servers{
			{URL: "http://localhost:8080/api"},
			{URL: "https://user.com/api"},
		}

		apiDef := &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		// Empty version name for non-versioned API
		result, err := ExtractUserServers(existingServers, apiDef, nil, config, "")
		require.NoError(t, err)

		require.Equal(t, 1, len(result))
		assert.Equal(t, "https://user.com/api", result[0].URL)
	})

	t.Run("handles mixed protocols correctly", func(t *testing.T) {
		t.Parallel()

		existingServers := openapi3.Servers{
			{URL: "http://localhost:8080/api"},  // Tyk HTTP
			{URL: "https://user-https.com/api"}, // User HTTPS
			{URL: "http://user-http.com/api"},   // User HTTP
		}

		apiDef := &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}

		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "localhost:8080",
		}

		result, err := ExtractUserServers(existingServers, apiDef, nil, config, "")
		require.NoError(t, err)

		require.Equal(t, 2, len(result))

		urls := make([]string, len(result))
		for i, server := range result {
			urls[i] = server.URL
		}

		assert.Contains(t, urls, "https://user-https.com/api")
		assert.Contains(t, urls, "http://user-http.com/api")
	})
}

// TestGenerateVersionedServers_Scenario1 tests that when versioning is enabled
// but no default version is set (or fallbackToDefault is false), the URL
// MUST include the version identifier.
func TestGenerateVersionedServers_Scenario1_VersionRequired(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	tests := []struct {
		name              string
		fallbackToDefault bool
		defaultVersion    string
		versionName       string
		expectedURLs      []string
		unexpectedURLs    []string
		description       string
	}{
		{
			name:              "no default version set, fallback false",
			fallbackToDefault: false,
			defaultVersion:    "",
			versionName:       "v1",
			expectedURLs: []string{
				"http://localhost:8080/api/v1",
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api",
			},
			description: "Without default or fallback, only versioned URL should exist",
		},
		{
			name:              "default version set but fallback false",
			fallbackToDefault: false,
			defaultVersion:    "v1",
			versionName:       "v1",
			expectedURLs: []string{
				"http://localhost:8080/api/v1",
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api",
			},
			description: "With default but no fallback, only versioned URL should exist",
		},
		{
			name:              "no default version but fallback true",
			fallbackToDefault: true,
			defaultVersion:    "",
			versionName:       "v1",
			expectedURLs: []string{
				"http://localhost:8080/api/v1",
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api",
			},
			description: "With fallback but no default, only versioned URL should exist",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Base API with versioning enabled
			baseAPI := &apidef.APIDefinition{
				APIID: "base-api-123",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					Name:              tt.versionName,
					Default:           tt.defaultVersion,
					FallbackToDefault: tt.fallbackToDefault,
					Location:          "url",
					BaseID:            "",
				},
			}

			// Generate servers
			servers := generateVersionedServers(baseAPI, baseAPI, config, tt.versionName)

			// Convert to URL strings for easier assertion
			urls := make([]string, len(servers))
			for i, s := range servers {
				urls[i] = s.url
			}

			// Verify expected URLs are present
			for _, expectedURL := range tt.expectedURLs {
				assert.Contains(t, urls, expectedURL,
					"%s: Expected URL %s should be present", tt.description, expectedURL)
			}

			// Verify unexpected URLs are NOT present
			for _, unexpectedURL := range tt.unexpectedURLs {
				assert.NotContains(t, urls, unexpectedURL,
					"%s: URL %s should NOT be present", tt.description, unexpectedURL)
			}
		})
	}
}

// TestGenerateVersionedServers_Scenario2 tests that when a base API has versioning
// enabled with a default version and fallbackToDefault is true, BOTH URLs are valid:
// 1. {protocol}://{host}/{listen-path}/{versionName}/
// 2. {protocol}://{host}/{listen-path}/
func TestGenerateVersionedServers_Scenario2_BaseAPIWithFallback(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	tests := []struct {
		name           string
		versionName    string
		defaultVersion string
		listenPath     string
		expectedURLs   []string
		description    string
	}{
		{
			name:           "base API with default v1 and fallback true",
			versionName:    "v1",
			defaultVersion: "v1",
			listenPath:     "/api",
			expectedURLs: []string{
				"http://localhost:8080/api/v1", // Versioned URL
				"http://localhost:8080/api",    // Fallback URL
			},
			description: "Base API should have both versioned and fallback URLs",
		},
		{
			name:           "base API with different version name",
			versionName:    "v2",
			defaultVersion: "v2",
			listenPath:     "/myapi",
			expectedURLs: []string{
				"http://localhost:8080/myapi/v2", // Versioned URL
				"http://localhost:8080/myapi",    // Fallback URL
			},
			description: "Base API with v2 should have both URLs",
		},
		{
			name:           "base API with nested listen path",
			versionName:    "v1",
			defaultVersion: "v1",
			listenPath:     "/api/service",
			expectedURLs: []string{
				"http://localhost:8080/api/service/v1", // Versioned URL
				"http://localhost:8080/api/service",    // Fallback URL
			},
			description: "Base API with nested path should have both URLs",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Base API with versioning enabled, default set, and fallback true
			baseAPI := &apidef.APIDefinition{
				APIID: "base-api-123",
				Proxy: apidef.ProxyConfig{
					ListenPath: tt.listenPath,
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					Name:              tt.versionName,
					Default:           tt.defaultVersion,
					FallbackToDefault: true,
					Location:          "url",
					BaseID:            "",
				},
			}

			// Generate servers
			servers := generateVersionedServers(baseAPI, baseAPI, config, tt.versionName)

			// Convert to URL strings for easier assertion
			urls := make([]string, len(servers))
			for i, s := range servers {
				urls[i] = s.url
			}

			// Verify both URLs are present
			assert.Equal(t, len(tt.expectedURLs), len(urls),
				"%s: Should have exactly %d URLs", tt.description, len(tt.expectedURLs))

			for _, expectedURL := range tt.expectedURLs {
				assert.Contains(t, urls, expectedURL,
					"%s: Expected URL %s should be present", tt.description, expectedURL)
			}
		})
	}
}

// TestGenerateVersionedServers_Scenario3 tests that for child version APIs,
// when the default version value (stored in baseAPI) is the same as the child
// version name, and fallbackToDefault is true, then the fallback URL
// {protocol}://{host}/{base-listen-path}/ makes sense for that specific version.
func TestGenerateVersionedServers_Scenario3_ChildAPIMatchingDefault(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	tests := []struct {
		name             string
		childVersionName string
		defaultVersion   string
		baseListenPath   string
		childListenPath  string
		isExternal       bool
		expectedURLs     []string
		unexpectedURLs   []string
		description      string
	}{
		{
			name:             "child API matching default version",
			childVersionName: "v1",
			defaultVersion:   "v1",
			baseListenPath:   "/api",
			childListenPath:  "/api-v1",
			isExternal:       true,
			expectedURLs: []string{
				"http://localhost:8080/api/v1", // Versioned URL through base
				"http://localhost:8080/api",    // Fallback URL (matches default)
				"http://localhost:8080/api-v1", // Direct access URL (external child)
			},
			description: "Child API matching default should have versioned, fallback, and direct URLs",
		},
		{
			name:             "child API NOT matching default version",
			childVersionName: "v2",
			defaultVersion:   "v1",
			baseListenPath:   "/api",
			childListenPath:  "/api-v2",
			isExternal:       true,
			expectedURLs: []string{
				"http://localhost:8080/api/v2", // Versioned URL through base
				"http://localhost:8080/api-v2", // Direct access URL (external child)
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api", // Fallback URL should NOT exist (not default version)
			},
			description: "Child API NOT matching default should NOT have fallback URL",
		},
		{
			name:             "internal child API matching default",
			childVersionName: "v1",
			defaultVersion:   "v1",
			baseListenPath:   "/api",
			childListenPath:  "/api-v1-internal",
			isExternal:       false,
			expectedURLs: []string{
				"http://localhost:8080/api/v1", // Versioned URL through base
				"http://localhost:8080/api",    // Fallback URL (matches default)
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api-v1-internal", // No direct URL (internal)
			},
			description: "Internal child API should not have direct access URL",
		},
		{
			name:             "internal child API NOT matching default",
			childVersionName: "v2",
			defaultVersion:   "v1",
			baseListenPath:   "/api",
			childListenPath:  "/api-v2-internal",
			isExternal:       false,
			expectedURLs: []string{
				"http://localhost:8080/api/v2", // Versioned URL through base
			},
			unexpectedURLs: []string{
				"http://localhost:8080/api",             // No fallback (not default)
				"http://localhost:8080/api-v2-internal", // No direct URL (internal)
			},
			description: "Internal child NOT matching default should only have versioned URL",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Base API with versioning enabled
			baseAPI := &apidef.APIDefinition{
				APIID: "base-api-123",
				Proxy: apidef.ProxyConfig{
					ListenPath: tt.baseListenPath,
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					Name:              "v1",
					Default:           tt.defaultVersion,
					FallbackToDefault: true,
					Location:          "url",
					BaseID:            "",
					Versions: map[string]string{
						tt.childVersionName: "child-api-456",
					},
				},
			}

			// Child API
			childAPI := &apidef.APIDefinition{
				APIID: "child-api-456",
				Proxy: apidef.ProxyConfig{
					ListenPath: tt.childListenPath,
				},
				Internal: !tt.isExternal,
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-api-123",
				},
			}

			// Generate servers for child API
			servers := generateVersionedServers(childAPI, baseAPI, config, tt.childVersionName)

			// Convert to URL strings for easier assertion
			urls := make([]string, len(servers))
			for i, s := range servers {
				urls[i] = s.url
			}

			// Verify expected URLs are present
			for _, expectedURL := range tt.expectedURLs {
				assert.Contains(t, urls, expectedURL,
					"%s: Expected URL %s should be present", tt.description, expectedURL)
			}

			// Verify unexpected URLs are NOT present
			for _, unexpectedURL := range tt.unexpectedURLs {
				assert.NotContains(t, urls, unexpectedURL,
					"%s: URL %s should NOT be present", tt.description, unexpectedURL)
			}
		})
	}
}

// TestGenerateVersionedServers_QueryParamVersioning tests that fallback URLs
// work correctly with query parameter versioning.
func TestGenerateVersionedServers_QueryParamVersioning(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	t.Run("base API with query param versioning and fallback", func(t *testing.T) {
		baseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true,
				Location:          "url-param",
				Key:               "version",
				BaseID:            "",
			},
		}

		servers := generateVersionedServers(baseAPI, baseAPI, config, "v1")

		urls := make([]string, len(servers))
		for i, s := range servers {
			urls[i] = s.url
		}

		// Should have both versioned (with query param) and fallback URLs
		assert.Contains(t, urls, "http://localhost:8080/api?version=v1",
			"Should have versioned URL with query param")
		assert.Contains(t, urls, "http://localhost:8080/api",
			"Should have fallback URL without query param")
	})

	t.Run("child API with query param versioning matching default", func(t *testing.T) {
		baseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true,
				Location:          "url-param",
				Key:               "ver",
				BaseID:            "",
				Versions: map[string]string{
					"v1": "child-api-456",
				},
			},
		}

		childAPI := &apidef.APIDefinition{
			APIID: "child-api-456",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api-v1",
			},
			Internal: false,
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base-api-123",
			},
		}

		servers := generateVersionedServers(childAPI, baseAPI, config, "v1")

		urls := make([]string, len(servers))
		for i, s := range servers {
			urls[i] = s.url
		}

		// Should have versioned, fallback (matches default), and direct URLs
		assert.Contains(t, urls, "http://localhost:8080/api?ver=v1",
			"Should have versioned URL with query param")
		assert.Contains(t, urls, "http://localhost:8080/api",
			"Should have fallback URL without query param")
		assert.Contains(t, urls, "http://localhost:8080/api-v1",
			"Should have direct access URL for external child")
	})
}

// TestRegenerateServers_FallbackToDefaultTransition tests that when fallbackToDefault
// is changed from true to false, the fallback URL is correctly removed.
func TestRegenerateServers_FallbackToDefaultTransition(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	t.Run("changing fallbackToDefault from true to false removes fallback URL", func(t *testing.T) {
		// Initial state: fallbackToDefault is true, default is set
		oldAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true, // Initially true
				Location:          "url",
				BaseID:            "",
			},
		}

		// Create OAS with initial servers (simulating what would have been generated)
		oasAPI := &OAS{T: openapi3.T{}}
		err := oasAPI.RegenerateServers(oldAPI, nil, nil, nil, config, "v1")
		require.NoError(t, err)

		// Verify initial state has both URLs
		initialURLs := make([]string, len(oasAPI.Servers))
		for i, s := range oasAPI.Servers {
			initialURLs[i] = s.URL
		}
		assert.Contains(t, initialURLs, "http://localhost:8080/api/v1", "Should have versioned URL initially")
		assert.Contains(t, initialURLs, "http://localhost:8080/api", "Should have fallback URL initially")

		// New state: fallbackToDefault is changed to false
		newAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: false, // Changed to false
				Location:          "url",
				BaseID:            "",
			},
		}

		// Regenerate servers with old and new state
		err = oasAPI.RegenerateServers(newAPI, oldAPI, nil, nil, config, "v1")
		require.NoError(t, err)

		// Verify final state has only versioned URL
		finalURLs := make([]string, len(oasAPI.Servers))
		for i, s := range oasAPI.Servers {
			finalURLs[i] = s.URL
		}
		assert.Contains(t, finalURLs, "http://localhost:8080/api/v1", "Should still have versioned URL")
		assert.NotContains(t, finalURLs, "http://localhost:8080/api", "Fallback URL should be removed")
		assert.Len(t, finalURLs, 2, "Should have 2 URLs after transition (absolute + relative)")
	})

	t.Run("changing fallbackToDefault from false to true adds fallback URL", func(t *testing.T) {
		// Initial state: fallbackToDefault is false
		oldAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: false, // Initially false
				Location:          "url",
				BaseID:            "",
			},
		}

		// Create OAS with initial servers
		oasAPI := &OAS{T: openapi3.T{}}
		err := oasAPI.RegenerateServers(oldAPI, nil, nil, nil, config, "v1")
		require.NoError(t, err)

		// Verify initial state has only versioned URL
		initialURLs := make([]string, len(oasAPI.Servers))
		for i, s := range oasAPI.Servers {
			initialURLs[i] = s.URL
		}
		assert.Contains(t, initialURLs, "http://localhost:8080/api/v1", "Should have versioned URL initially")
		assert.NotContains(t, initialURLs, "http://localhost:8080/api", "Should NOT have fallback URL initially")

		// New state: fallbackToDefault is changed to true
		newAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true, // Changed to true
				Location:          "url",
				BaseID:            "",
			},
		}

		// Regenerate servers with old and new state
		err = oasAPI.RegenerateServers(newAPI, oldAPI, nil, nil, config, "v1")
		require.NoError(t, err)

		// Verify final state has both URLs
		finalURLs := make([]string, len(oasAPI.Servers))
		for i, s := range oasAPI.Servers {
			finalURLs[i] = s.URL
		}
		assert.Contains(t, finalURLs, "http://localhost:8080/api/v1", "Should have versioned URL")
		assert.Contains(t, finalURLs, "http://localhost:8080/api", "Fallback URL should be added")
		assert.Len(t, finalURLs, 4, "Should have 4 URLs after transition (2 absolute + 2 relative)")
	})

	t.Run("preserves user servers during fallbackToDefault transition", func(t *testing.T) {
		// Initial state: fallbackToDefault is true
		oldAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true,
				Location:          "url",
				BaseID:            "",
			},
		}

		// Create OAS with initial servers + user server
		oasAPI := &OAS{T: openapi3.T{}}
		err := oasAPI.RegenerateServers(oldAPI, nil, nil, nil, config, "v1")
		require.NoError(t, err)

		// Add a user-provided server
		oasAPI.Servers = append(oasAPI.Servers, &openapi3.Server{
			URL: "https://my-custom-upstream.com/api",
		})

		// Verify we have Tyk servers + user server
		assert.Len(t, oasAPI.Servers, 5, "Should have 4 Tyk URLs (2 absolute + 2 relative) + 1 user URL")

		// New state: fallbackToDefault changed to false
		newAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: false,
				Location:          "url",
				BaseID:            "",
			},
		}

		// Regenerate servers
		err = oasAPI.RegenerateServers(newAPI, oldAPI, nil, nil, config, "v1")
		require.NoError(t, err)

		// Verify final state
		finalURLs := make([]string, len(oasAPI.Servers))
		for i, s := range oasAPI.Servers {
			finalURLs[i] = s.URL
		}

		assert.Contains(t, finalURLs, "http://localhost:8080/api/v1", "Should have versioned Tyk URL")
		assert.NotContains(t, finalURLs, "http://localhost:8080/api", "Fallback Tyk URL should be removed")
		assert.Contains(t, finalURLs, "https://my-custom-upstream.com/api", "User server should be preserved")
		assert.Len(t, finalURLs, 3, "Should have 2 Tyk URLs (1 absolute + 1 relative) + 1 user URL")
	})
}

func TestRegenerateServers_BaseAPILosesFallbackWhenNewDefaultSet(t *testing.T) {
	t.Parallel()

	config := ServerRegenerationConfig{
		Protocol:    "http://",
		DefaultHost: "localhost:8080",
	}

	t.Run("base API loses fallback URL when new version becomes default", func(t *testing.T) {
		oldBaseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true,
				Location:          "url",
				BaseID:            "",
				Versions:          map[string]string{},
			},
		}

		baseOAS := &OAS{T: openapi3.T{}}
		err := baseOAS.RegenerateServers(oldBaseAPI, nil, oldBaseAPI, nil, config, "v1")
		require.NoError(t, err)

		initialURLs := make([]string, len(baseOAS.Servers))
		for i, s := range baseOAS.Servers {
			initialURLs[i] = s.URL
		}
		assert.Contains(t, initialURLs, "http://localhost:8080/api/v1")
		assert.Contains(t, initialURLs, "http://localhost:8080/api")
		assert.Len(t, initialURLs, 4, "Initial: 2 absolute + 2 relative")

		newBaseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v2",
				FallbackToDefault: true,
				Location:          "url",
				BaseID:            "",
				Versions: map[string]string{
					"v2": "child-api-456",
				},
			},
		}

		err = baseOAS.RegenerateServers(newBaseAPI, oldBaseAPI, newBaseAPI, oldBaseAPI, config, "v1")
		require.NoError(t, err)

		finalURLs := make([]string, len(baseOAS.Servers))
		for i, s := range baseOAS.Servers {
			finalURLs[i] = s.URL
		}
		assert.Contains(t, finalURLs, "http://localhost:8080/api/v1")
		assert.NotContains(t, finalURLs, "http://localhost:8080/api")
		assert.Len(t, finalURLs, 2, "Final: 1 absolute + 1 relative")
	})

	t.Run("child API gets fallback URL when set as default", func(t *testing.T) {
		baseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v2",
				FallbackToDefault: true,
				Location:          "url",
				BaseID:            "",
				Versions: map[string]string{
					"v2": "child-api-456",
				},
			},
		}

		childV2 := &apidef.APIDefinition{
			APIID: "child-api-456",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  false,
				Name:     "v2",
				Location: "url",
				BaseID:   "base-api-123",
			},
		}

		childOAS := &OAS{T: openapi3.T{}}
		err := childOAS.RegenerateServers(childV2, nil, baseAPI, nil, config, "v2")
		require.NoError(t, err)

		childURLs := make([]string, len(childOAS.Servers))
		for i, s := range childOAS.Servers {
			childURLs[i] = s.URL
		}
		assert.Contains(t, childURLs, "http://localhost:8080/api/v2")
		assert.Contains(t, childURLs, "http://localhost:8080/api")
		assert.Contains(t, childURLs, "http://localhost:8080/api-v2")
		assert.Len(t, childURLs, 6, "3 absolute + 3 relative")
	})

	t.Run("non-default child API does not get fallback URL", func(t *testing.T) {
		baseAPI := &apidef.APIDefinition{
			APIID: "base-api-123",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v2",
				FallbackToDefault: true,
				Location:          "url",
				BaseID:            "",
				Versions: map[string]string{
					"v2": "child-api-456",
					"v3": "child-api-789",
				},
			},
		}

		childV3 := &apidef.APIDefinition{
			APIID: "child-api-789",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api-v3",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:  false,
				Name:     "v3",
				Location: "url",
				BaseID:   "base-api-123",
			},
		}

		childOAS := &OAS{T: openapi3.T{}}
		err := childOAS.RegenerateServers(childV3, nil, baseAPI, nil, config, "v3")
		require.NoError(t, err)

		childURLs := make([]string, len(childOAS.Servers))
		for i, s := range childOAS.Servers {
			childURLs[i] = s.URL
		}
		assert.Contains(t, childURLs, "http://localhost:8080/api/v3")
		assert.NotContains(t, childURLs, "http://localhost:8080/api")
		assert.Contains(t, childURLs, "http://localhost:8080/api-v3")
		assert.Len(t, childURLs, 4, "2 absolute + 2 relative")
	})
}

func TestDetermineHosts_MDCB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apiData  *apidef.APIDefinition
		config   ServerRegenerationConfig
		expected []string
		comment  string
	}{
		{
			name: "MDCB: no edge endpoints configured → relative paths",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{},
			},
			expected: []string{""},
			comment:  "Scenario 1: No edge endpoints, should return relative path",
		},
		{
			name: "MDCB: API has no tags → relative path",
			apiData: &apidef.APIDefinition{
				Tags: []string{},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{""},
			comment:  "Scenario 2: API has no tags, should return relative path",
		},
		{
			name: "MDCB: API tags don't match any edge endpoint → relative paths only",
			apiData: &apidef.APIDefinition{
				Tags: []string{"dev", "staging"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod", "backup"}},
				},
			},
			expected: []string{""},
			comment:  "Scenario 3: No tag matches, should return relative path",
		},
		{
			name: "MDCB Scenario 4a: all API tags match edge endpoints → matching endpoints + relative",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod", "us"}},
					{Endpoint: "http://edge3.example.com", Tags: []string{"dev"}},
				},
			},
			expected: []string{"http://edge1.example.com", "http://edge2.example.com", ""},
			comment:  "Scenario 4a: All API tags matched, should return matching endpoints + relative path",
		},
		{
			name: "MDCB Scenario 4b: some API tags match, some don't → endpoints + relative paths",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod", "nonexistent"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod", "us"}},
					{Endpoint: "http://edge3.example.com", Tags: []string{"dev"}},
				},
			},
			expected: []string{"http://edge1.example.com", "http://edge2.example.com", ""},
			comment:  "Scenario 4b: Some tags didn't match, should return matching endpoints + relative path",
		},
		{
			name: "MDCB: custom domain takes precedence even in hybrid mode",
			apiData: &apidef.APIDefinition{
				Domain: "api.custom.com",
				Tags:   []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{"api.custom.com"},
			comment:  "Custom domain should override MDCB logic",
		},
		{
			name: "Standard mode: edge endpoints with matching tags",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: false,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{"http://edge1.example.com", "http://edge2.example.com", ""},
			comment:  "Standard mode should return matching endpoints with relative path",
		},
		{
			name: "Standard mode: no matching tags → relative paths",
			apiData: &apidef.APIDefinition{
				Tags: []string{"dev"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: false,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expected: []string{""},
			comment:  "Standard mode with no tag matches should return relative paths",
		},
		{
			name: "Standard mode: some tags match, some don't → endpoints + relative paths",
			apiData: &apidef.APIDefinition{
				Tags: []string{"external", "asdadasdasd"},
			},
			config: ServerRegenerationConfig{
				DefaultHost:   "localhost:8080",
				HybridEnabled: false,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://ddd", Tags: []string{"external"}},
				},
			},
			expected: []string{"http://ddd", ""},
			comment:  "Standard mode with mixed tag matches should return matching endpoints + relative paths",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := determineHosts(tt.apiData, tt.config)
			assert.Equal(t, tt.expected, result, tt.comment)
		})
	}
}

func TestFindEndpointsMatchingTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		apiTags       []string
		edgeEndpoints []EdgeEndpoint
		expected      []string
	}{
		{
			name:          "no endpoints",
			apiTags:       []string{"prod"},
			edgeEndpoints: []EdgeEndpoint{},
			expected:      []string{},
		},
		{
			name:    "single match",
			apiTags: []string{"prod"},
			edgeEndpoints: []EdgeEndpoint{
				{Endpoint: "http://edge1.com", Tags: []string{"prod"}},
			},
			expected: []string{"http://edge1.com"},
		},
		{
			name:    "multiple matches",
			apiTags: []string{"prod"},
			edgeEndpoints: []EdgeEndpoint{
				{Endpoint: "http://edge1.com", Tags: []string{"prod"}},
				{Endpoint: "http://edge2.com", Tags: []string{"prod", "backup"}},
			},
			expected: []string{"http://edge1.com", "http://edge2.com"},
		},
		{
			name:    "no matches",
			apiTags: []string{"dev"},
			edgeEndpoints: []EdgeEndpoint{
				{Endpoint: "http://edge1.com", Tags: []string{"prod"}},
			},
			expected: []string{},
		},
		{
			name:    "API has multiple tags, one matches",
			apiTags: []string{"dev", "prod", "staging"},
			edgeEndpoints: []EdgeEndpoint{
				{Endpoint: "http://edge1.com", Tags: []string{"prod"}},
			},
			expected: []string{"http://edge1.com"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := findEndpointsMatchingTags(tt.apiTags, tt.edgeEndpoints)
			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestHasAnyTagMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		apiTags      []string
		endpointTags []string
		expected     bool
	}{
		{
			name:         "single match",
			apiTags:      []string{"prod"},
			endpointTags: []string{"prod"},
			expected:     true,
		},
		{
			name:         "no match",
			apiTags:      []string{"dev"},
			endpointTags: []string{"prod"},
			expected:     false,
		},
		{
			name:         "multiple tags, one matches",
			apiTags:      []string{"dev", "staging"},
			endpointTags: []string{"staging", "prod"},
			expected:     true,
		},
		{
			name:         "empty API tags",
			apiTags:      []string{},
			endpointTags: []string{"prod"},
			expected:     false,
		},
		{
			name:         "empty endpoint tags",
			apiTags:      []string{"prod"},
			endpointTags: []string{},
			expected:     false,
		},
		{
			name:         "both empty",
			apiTags:      []string{},
			endpointTags: []string{},
			expected:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := hasAnyTagMatch(tt.apiTags, tt.endpointTags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildTagSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tags     []string
		expected map[string]bool
	}{
		{
			name:     "empty tags",
			tags:     []string{},
			expected: map[string]bool{},
		},
		{
			name: "single tag",
			tags: []string{"prod"},
			expected: map[string]bool{
				"prod": true,
			},
		},
		{
			name: "multiple tags",
			tags: []string{"prod", "us", "staging"},
			expected: map[string]bool{
				"prod":    true,
				"us":      true,
				"staging": true,
			},
		},
		{
			name: "duplicate tags",
			tags: []string{"prod", "prod", "dev"},
			expected: map[string]bool{
				"prod": true,
				"dev":  true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := buildTagSet(tt.tags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAppendRelativePathIfNotPresent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty list",
			input:    []string{},
			expected: []string{""},
		},
		{
			name:     "list without relative path",
			input:    []string{"http://edge1.com", "http://edge2.com"},
			expected: []string{"http://edge1.com", "http://edge2.com", ""},
		},
		{
			name:     "list already has relative path",
			input:    []string{"http://edge1.com", "", "http://edge2.com"},
			expected: []string{"http://edge1.com", "", "http://edge2.com"},
		},
		{
			name:     "list with only relative path",
			input:    []string{""},
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := appendRelativePathIfNotPresent(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateStandardServers_MDCB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		apiData       *apidef.APIDefinition
		config        ServerRegenerationConfig
		expectedCount int
		expectedURLs  []string
		comment       string
	}{
		{
			name: "MDCB Scenario 4a: all tags match → absolute + relative URLs",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod"},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:      "http://",
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod"}},
				},
			},
			expectedCount: 3,
			expectedURLs: []string{
				"http://edge1.example.com/api",
				"http://edge2.example.com/api",
				"/api",
			},
			comment: "Scenario 4a: All tags matched, should include matching endpoints + relative path",
		},
		{
			name: "MDCB Scenario 4b: some tags don't match → absolute + relative URLs",
			apiData: &apidef.APIDefinition{
				Tags: []string{"prod", "nonexistent"},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:      "http://",
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
					{Endpoint: "http://edge2.example.com", Tags: []string{"prod"}},
				},
			},
			expectedCount: 3,
			expectedURLs: []string{
				"http://edge1.example.com/api",
				"http://edge2.example.com/api",
				"/api", // Relative path for non-matching tag
			},
			comment: "Scenario 4b: Some tags didn't match, should include edge endpoints + relative path",
		},
		{
			name: "MDCB with no matching tags generates only relative URL",
			apiData: &apidef.APIDefinition{
				Tags: []string{"dev"},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:      "http://",
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expectedCount: 1,
			expectedURLs: []string{
				"/api", // Only relative path
			},
			comment: "MDCB with no matching tags should only generate relative path",
		},
		{
			name: "MDCB with no API tags generates relative URL",
			apiData: &apidef.APIDefinition{
				Tags: []string{},
				Proxy: apidef.ProxyConfig{
					ListenPath: "/api",
				},
			},
			config: ServerRegenerationConfig{
				Protocol:      "http://",
				DefaultHost:   "localhost:8080",
				HybridEnabled: true,
				EdgeEndpoints: []EdgeEndpoint{
					{Endpoint: "http://edge1.example.com", Tags: []string{"prod"}},
				},
			},
			expectedCount: 1,
			expectedURLs:  []string{"/api"},
			comment:       "MDCB with no API tags should generate relative URL",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := generateStandardServers(tt.apiData, tt.config)
			assert.Equal(t, tt.expectedCount, len(result), tt.comment)

			for _, expectedURL := range tt.expectedURLs {
				found := false
				for _, server := range result {
					if server.url == expectedURL {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected URL %s not found. %s", expectedURL, tt.comment)
			}
		})
	}
}
