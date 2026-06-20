package oas

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-059
// SW-REQ-059:nominal:nominal
// SW-REQ-059:boundary:nominal
// SW-REQ-059:error_handling:negative
// SW-REQ-059:determinism:nominal
func TestServerRegenerationPreservesTykAndUserServerShapes(t *testing.T) {
	t.Run("host tag and url helpers preserve deterministic server shapes", func(t *testing.T) {
		tagSet := buildTagSet([]string{"prod", "prod", "edge"})
		assert.Equal(t, map[string]bool{"prod": true, "edge": true}, tagSet)
		assert.True(t, hasAnyTagMatch([]string{"dev", "prod"}, []string{"prod"}))
		assert.False(t, hasAnyTagMatch([]string{"dev"}, []string{"prod"}))
		assert.Equal(t, []string{"https://edge-a.example.com", "https://edge-b.example.com"}, findEndpointsMatchingTags(
			[]string{"prod"},
			[]EdgeEndpoint{
				{Endpoint: "https://edge-a.example.com", Tags: []string{"prod"}},
				{Endpoint: "https://edge-b.example.com", Tags: []string{"prod", "backup"}},
				{Endpoint: "https://edge-c.example.com", Tags: []string{"dev"}},
			},
		))
		assert.Equal(t, []string{"https://edge.example.com", ""}, appendRelativePathIfNotPresent([]string{"https://edge.example.com"}))
		assert.Equal(t, []string{"", "https://edge.example.com"}, appendRelativePathIfNotPresent([]string{"", "https://edge.example.com"}))

		config := ServerRegenerationConfig{
			Protocol:    "https://",
			DefaultHost: "default.example.com",
			EdgeEndpoints: []EdgeEndpoint{
				{Endpoint: "https://edge.example.com", Tags: []string{"prod"}},
			},
		}
		assert.Equal(t, []string{"api.example.com"}, determineHosts(&apidef.APIDefinition{Domain: "api.example.com", Tags: []string{"prod"}}, config))
		assert.Equal(t, []string{"default.example.com", ""}, determineHosts(&apidef.APIDefinition{TagsDisabled: true, Tags: []string{"prod"}}, config))
		assert.Equal(t, []string{"https://edge.example.com", ""}, determineHosts(&apidef.APIDefinition{Tags: []string{"prod"}}, config))
		assert.Equal(t, []string{""}, determineHosts(&apidef.APIDefinition{Tags: []string{"dev"}}, config))
		assert.Equal(t, []string{""}, determineHosts(&apidef.APIDefinition{}, ServerRegenerationConfig{DefaultHost: "default.example.com", HybridEnabled: true}))

		assert.Equal(t, "https://api.example.com/pets/v1", buildServerURL("https://", "api.example.com/", "pets//v1"))
		assert.Equal(t, "/pets/v1", buildServerURL("https://", "", "/pets//v1"))
		assert.Equal(t, "http://edge.example.com/pets", buildServerURL("https://", "http://edge.example.com", "/pets"))

		versionedURL, description := buildVersionedServerURL("https://", "api.example.com", "/pets", "url", "", "v2")
		assert.Equal(t, "https://api.example.com/pets/v2", versionedURL)
		assert.Empty(t, description)
		versionedURL, _ = buildVersionedServerURL("https://", "api.example.com", "/pets", "url-param", "version", "v2")
		assert.Equal(t, "https://api.example.com/pets?version=v2", versionedURL)
		versionedURL, _ = buildVersionedServerURL("https://", "api.example.com", "/pets", "header", "X-Version", "v2")
		assert.Equal(t, "https://api.example.com/pets", versionedURL)
		versionedURL, _ = buildVersionedServerURL("https://", "api.example.com", "/pets", "unknown", "", "v2")
		assert.Equal(t, "https://api.example.com/pets/v2", versionedURL)

		assert.Equal(t, "https://api.example.com/pets", normalizeServerURL("https://api.example.com//pets/"))
		assert.Equal(t, "%zz", normalizeServerURL("%zz/"))
		assert.True(t, containsString([]string{"a", "b"}, "b"))
		assert.False(t, containsString([]string{"a", "b"}, "c"))
	})

	t.Run("standard and versioned tyk servers are generated from api definition state", func(t *testing.T) {
		config := ServerRegenerationConfig{
			Protocol:    "http://",
			DefaultHost: "gateway.local",
			EdgeEndpoints: []EdgeEndpoint{
				{Endpoint: "https://edge-a.example.com", Tags: []string{"prod"}},
				{Endpoint: "https://edge-b.example.com", Tags: []string{"prod"}},
			},
		}
		standardAPI := &apidef.APIDefinition{
			Tags: []string{"prod"},
			Proxy: apidef.ProxyConfig{
				ListenPath: "/standard",
			},
		}
		standardServers := generateStandardServers(standardAPI, config)
		assertServerInfoURLs(t, standardServers, []string{"https://edge-a.example.com/standard", "https://edge-b.example.com/standard", "/standard"})

		baseAPI := &apidef.APIDefinition{
			APIID: "base",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products",
			},
			VersionDefinition: apidef.VersionDefinition{
				Enabled:           true,
				Name:              "v1",
				Default:           "v1",
				FallbackToDefault: true,
				Location:          "url",
				Versions: map[string]string{
					"v1": "base",
					"v2": "child",
				},
			},
		}
		baseServers := generateTykServers(baseAPI, nil, ServerRegenerationConfig{Protocol: "http://", DefaultHost: "gateway.local"}, "")
		assertServerInfoURLs(t, baseServers, []string{"http://gateway.local/products/v1", "/products/v1", "http://gateway.local/products", "/products"})

		childAPI := &apidef.APIDefinition{
			APIID: "child",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/products-v2",
			},
			VersionDefinition: apidef.VersionDefinition{
				BaseID: "base",
			},
		}
		childServers := generateVersionedServers(childAPI, baseAPI, ServerRegenerationConfig{Protocol: "http://", DefaultHost: "gateway.local"}, "v2")
		assertServerInfoURLs(t, childServers, []string{"http://gateway.local/products/v2", "/products/v2", "http://gateway.local/products-v2", "/products-v2"})

		oas := &OAS{}
		publicServers := oas.GenerateTykServers(childAPI, baseAPI, ServerRegenerationConfig{Protocol: "http://", DefaultHost: "gateway.local"}, "v2")
		assertServerURLs(t, publicServers, []string{"http://gateway.local/products/v2", "/products/v2", "http://gateway.local/products-v2", "/products-v2"})
	})

	t.Run("regeneration replaces old tyk servers preserves user servers and propagates invalid generated urls", func(t *testing.T) {
		oldAPI := &apidef.APIDefinition{
			APIID: "api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/old",
			},
		}
		newAPI := &apidef.APIDefinition{
			APIID: "api",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/new",
			},
		}
		config := ServerRegenerationConfig{Protocol: "http://", DefaultHost: "gateway.local"}
		oas := &OAS{T: openapi3.T{Servers: openapi3.Servers{
			{URL: "http://gateway.local/old"},
			{URL: "https://user.example.com/root"},
			{URL: "http://gateway.local/new"},
		}}}

		require.NoError(t, oas.RegenerateServers(newAPI, oldAPI, nil, nil, config, ""))
		assertServerURLs(t, oas.Servers, []string{"http://gateway.local/new", "/new", "https://user.example.com/root"})
		assert.Equal(t, "http://gateway.local/new", oas.Servers[0].URL)

		filtered := removeTykGeneratedURLs(openapi3.Servers{
			{URL: "http://gateway.local/new/"},
			{URL: "https://user.example.com/root"},
		}, []string{"http://gateway.local/new"})
		assertServerURLs(t, filtered, []string{"https://user.example.com/root"})

		extracted, err := ExtractUserServers(oas.Servers, newAPI, nil, config, "")
		require.NoError(t, err)
		assertServerURLs(t, extracted, []string{"https://user.example.com/root"})

		emptyExtracted, err := ExtractUserServers(nil, newAPI, nil, config, "")
		require.NoError(t, err)
		assert.Empty(t, emptyExtracted)

		err = (&OAS{}).RegenerateServers(&apidef.APIDefinition{
			Tags: []string{"bad"},
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}, nil, nil, nil, ServerRegenerationConfig{
			Protocol: "http://",
			EdgeEndpoints: []EdgeEndpoint{
				{Endpoint: "http://{bad", Tags: []string{"bad"}},
			},
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add Tyk servers")
	})

	t.Run("child update decisions are limited to version URL affecting fields", func(t *testing.T) {
		base := func() *apidef.APIDefinition {
			return &apidef.APIDefinition{
				APIID: "base",
				Proxy: apidef.ProxyConfig{
					ListenPath: "/products",
				},
				VersionDefinition: apidef.VersionDefinition{
					Enabled:           true,
					BaseID:            "base",
					Location:          "url",
					Key:               "version",
					Default:           "v1",
					FallbackToDefault: true,
					Versions: map[string]string{
						"v1": "base",
						"v2": "child",
					},
				},
			}
		}

		assert.False(t, ShouldUpdateChildAPIs(nil, base()))
		assert.False(t, ShouldUpdateChildAPIs(&apidef.APIDefinition{APIID: "child", VersionDefinition: apidef.VersionDefinition{BaseID: "base"}}, base()))
		assert.False(t, ShouldUpdateChildAPIs(base(), nil))

		oldAPI := base()
		newAPI := base()
		newAPI.Domain = "api.example.com"
		assert.False(t, ShouldUpdateChildAPIs(newAPI, oldAPI))

		for _, mutate := range []func(*apidef.APIDefinition){
			func(api *apidef.APIDefinition) { api.VersionDefinition.Location = "url-param" },
			func(api *apidef.APIDefinition) { api.VersionDefinition.Key = "api-version" },
			func(api *apidef.APIDefinition) { api.Proxy.ListenPath = "/new-products" },
			func(api *apidef.APIDefinition) { api.VersionDefinition.FallbackToDefault = false },
			func(api *apidef.APIDefinition) { api.VersionDefinition.Default = "v2" },
		} {
			candidate := base()
			mutate(candidate)
			assert.True(t, ShouldUpdateChildAPIs(candidate, oldAPI))
		}

		assert.False(t, ShouldUpdateOldDefaultChild(false, "v1", "v2"))
		assert.False(t, ShouldUpdateOldDefaultChild(true, "", "v2"))
		assert.False(t, ShouldUpdateOldDefaultChild(true, "v1", "v1"))
		assert.False(t, ShouldUpdateOldDefaultChild(true, apidef.Self, "v2"))
		assert.True(t, ShouldUpdateOldDefaultChild(true, "v1", "v2"))
	})

	t.Run("repeated generation is deterministic", func(t *testing.T) {
		api := &apidef.APIDefinition{
			APIID: "api",
			Tags:  []string{"prod"},
			Proxy: apidef.ProxyConfig{
				ListenPath: "/api",
			},
		}
		config := ServerRegenerationConfig{
			Protocol:    "https://",
			DefaultHost: "gateway.local",
			EdgeEndpoints: []EdgeEndpoint{
				{Endpoint: "https://edge.example.com", Tags: []string{"prod"}},
			},
		}

		first := generateTykServers(api, nil, config, "")
		second := generateTykServers(api, nil, config, "")
		assert.Equal(t, serverInfoURLs(first), serverInfoURLs(second))
	})
}

func assertServerInfoURLs(t *testing.T, servers []serverInfo, expected []string) {
	t.Helper()
	assert.ElementsMatch(t, expected, serverInfoURLs(servers))
}

func serverInfoURLs(servers []serverInfo) []string {
	urls := make([]string, len(servers))
	for i, server := range servers {
		urls[i] = server.url
	}
	return urls
}

func assertServerURLs(t *testing.T, servers openapi3.Servers, expected []string) {
	t.Helper()
	urls := make([]string, len(servers))
	for i, server := range servers {
		urls[i] = strings.TrimSuffix(server.URL, "/")
	}
	assert.ElementsMatch(t, expected, urls)
}
