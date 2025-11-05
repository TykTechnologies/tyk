package oas

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

// ServerRegenerationConfig holds the configuration required for server URL regeneration.
type ServerRegenerationConfig struct {
	// Protocol is the URL scheme (http:// or https://).
	Protocol string
	// DefaultHost is the default gateway host (e.g., "localhost:8080").
	DefaultHost string
	// EdgeEndpoints contains edge gateway configurations.
	EdgeEndpoints []EdgeEndpoint
}

// EdgeEndpoint represents an edge gateway endpoint configuration.
type EdgeEndpoint struct {
	// Endpoint is the edge gateway URL (e.g., "http://edge1.example.com").
	Endpoint string
	// Tags are the tags associated with this edge gateway.
	Tags []string
}

// serverInfo holds information about a server URL to be added to OAS.
type serverInfo struct {
	url         string
	description string
}

// RegenerateServers updates the servers section of an OAS API definition
//  1. Computes old Tyk-generated servers from oldAPIData state (if provided)
//  2. Removes old Tyk servers from the OAS spec
//  3. Generates new Tyk servers based on newAPIData configuration
//  4. Merges them: Tyk servers first, then user servers
//  5. Deduplicates by normalized URL
func (s *OAS) RegenerateServers(
	newAPIData *apidef.APIDefinition,
	oldAPIData *apidef.APIDefinition,
	newBaseAPI *apidef.APIDefinition,
	oldBaseAPI *apidef.APIDefinition,
	config ServerRegenerationConfig,
	versionName string,
) error {
	// Step 1: Compute old Tyk URLs from old state (regenerate what they were)
	var oldTykURLs []string
	if oldAPIData != nil {
		oldServerInfos := generateTykServers(oldAPIData, oldBaseAPI, config, versionName)
		oldTykURLs = make([]string, len(oldServerInfos))
		for i, info := range oldServerInfos {
			oldTykURLs[i] = info.url
		}
	}

	// Step 2: Remove old Tyk-generated servers (preserves user-provided servers)
	userServers := removeTykGeneratedURLs(s.Servers, oldTykURLs)

	// Step 3: Generate new Tyk servers
	tykServerInfos := generateTykServers(newAPIData, newBaseAPI, config, versionName)

	// Step 4: Add Tyk servers first
	tykURLs := make([]string, len(tykServerInfos))
	for i, info := range tykServerInfos {
		tykURLs[i] = info.url
	}

	// Start with empty servers, then add Tyk servers
	s.Servers = openapi3.Servers{}
	if err := s.AddServers(tykURLs...); err != nil {
		return fmt.Errorf("failed to add Tyk servers: %w", err)
	}

	// Step 5: Add user servers back, deduplicating by normalized URL
	existingURLs := make(map[string]bool)
	for _, server := range s.Servers {
		existingURLs[normalizeServerURL(server.URL)] = true
	}

	// Add user servers that don't conflict with Tyk servers
	for _, userServer := range userServers {
		normalized := normalizeServerURL(userServer.URL)
		if !existingURLs[normalized] {
			s.Servers = append(s.Servers, userServer)
			existingURLs[normalized] = true
		}
	}

	return nil
}

// generateTykServers generates all Tyk-managed server URLs for an API.
func generateTykServers(
	apiData *apidef.APIDefinition,
	baseAPI *apidef.APIDefinition,
	config ServerRegenerationConfig,
	versionName string,
) []serverInfo {
	isChildAPI := apiData.IsChildAPI() ||
		(baseAPI != nil && baseAPI.APIID != apiData.APIID && baseAPI.VersionDefinition.Enabled)

	if isChildAPI {
		return generateVersionedServers(apiData, baseAPI, config, versionName)
	}

	if apiData.IsBaseAPIWithVersioning() {
		return generateVersionedServers(apiData, apiData, config, apiData.VersionDefinition.Name)
	}

	return generateStandardServers(apiData, config)
}

// generateStandardServers generates server URLs for non-versioned APIs.
func generateStandardServers(apiData *apidef.APIDefinition, config ServerRegenerationConfig) []serverInfo {
	hosts := determineHosts(apiData, config)
	servers := make([]serverInfo, 0, len(hosts))

	for _, host := range hosts {
		serverURL := buildServerURL(config.Protocol, host, apiData.Proxy.ListenPath)
		servers = append(servers, serverInfo{
			url:         serverURL,
			description: "",
		})
	}

	return servers
}

// generateVersionedServers generates server URLs for versioned child APIs.
// It builds URLs according to the base API's versioning method.
func generateVersionedServers(
	apiData *apidef.APIDefinition,
	baseAPI *apidef.APIDefinition,
	config ServerRegenerationConfig,
	versionName string,
) []serverInfo {
	// Use provided base API or fallback to generating as standard API
	if baseAPI == nil {
		return generateStandardServers(apiData, config)
	}

	if versionName == "" {
		for name, versionID := range baseAPI.VersionDefinition.Versions {
			if versionID == apiData.APIID {
				versionName = name
				break
			}
		}

		if versionName == "" {
			return generateStandardServers(apiData, config)
		}
	}

	versionLocation := baseAPI.VersionDefinition.Location
	versionKey := baseAPI.VersionDefinition.Key
	baseListenPath := baseAPI.Proxy.ListenPath

	hosts := determineHosts(apiData, config)
	servers := make([]serverInfo, 0, len(hosts)*2) // *2 for potential direct access URLs

	// Determine if this API is the base API itself or a child
	isBaseAPI := apiData.APIID == baseAPI.APIID

	// Check if we should add a fallback URL (without version identifier)
	// This applies when:
	// 1. FallbackToDefault is enabled in base API's versioning config
	// 2. AND a default version is explicitly set (not empty)
	// 3. AND versioning is not header-based
	// 4. AND either:
	//    a) This is the base API itself (always add fallback URL when conditions met)
	//    b) This is a child API and its version name matches the default version
	shouldAddFallbackURL := baseAPI.VersionDefinition.FallbackToDefault &&
		baseAPI.VersionDefinition.Default != "" &&
		baseAPI.VersionDefinition.Location != "header" &&
		(isBaseAPI || versionName == baseAPI.VersionDefinition.Default)

	// Scenario 1 & 2: Always add versioned URLs
	// - Scenario 1: Versioning enabled, no default or no fallback → version required
	// - Scenario 2: Versioning enabled, default set, fallback true → version optional but valid
	for _, host := range hosts {
		versionedURL, description := buildVersionedServerURL(
			config.Protocol, host, baseListenPath,
			versionLocation, versionKey, versionName,
		)

		servers = append(servers, serverInfo{
			url:         versionedURL,
			description: description,
		})
	}

	// Add fallback URL (without version) when appropriate
	// This handles:
	// - Scenario 2: Base API with default version and fallback enabled
	// - Scenario 3: Child API matching default version with fallback enabled
	if shouldAddFallbackURL {
		for _, host := range hosts {
			fallbackURL := buildServerURL(config.Protocol, host, baseListenPath)
			servers = append(servers, serverInfo{
				url:         fallbackURL,
				description: "",
			})
		}
	}

	// If API is external AND it's a child API (not the base itself), also add direct access URLs
	// This is for child APIs that have their own listen paths separate from the base API
	if !apiData.Internal && !isBaseAPI {
		for _, host := range hosts {
			directURL := buildServerURL(config.Protocol, host, apiData.Proxy.ListenPath)
			servers = append(servers, serverInfo{
				url:         directURL,
				description: "",
			})
		}
	}

	return servers
}

// determineHosts determines which hosts to use for server URL generation.
// Priority: Custom Domain > Edge Endpoints > Default Host
func determineHosts(apiData *apidef.APIDefinition, config ServerRegenerationConfig) []string {
	// Priority 1: Custom domain
	if apiData.Domain != "" {
		return []string{apiData.Domain}
	}

	// Priority 2: Edge endpoints matching API tags
	if len(config.EdgeEndpoints) > 0 && len(apiData.Tags) > 0 {
		hosts := make([]string, 0, len(config.EdgeEndpoints))
		for _, endpoint := range config.EdgeEndpoints {
			endpointTagsMap := make(map[string]bool, len(endpoint.Tags))
			for _, tag := range endpoint.Tags {
				endpointTagsMap[tag] = true
			}

			for _, apiTag := range apiData.Tags {
				if endpointTagsMap[apiTag] {
					hosts = append(hosts, endpoint.Endpoint)
					break
				}
			}
		}

		if len(hosts) > 0 {
			return hosts
		}
	}

	// Priority 3: Default host
	return []string{config.DefaultHost}
}

// buildServerURL constructs a server URL from protocol, host, and path.
func buildServerURL(protocol, host, listenPath string) string {
	if !strings.HasPrefix(listenPath, "/") {
		listenPath = "/" + listenPath
	}

	host = strings.TrimSuffix(host, "/")

	// Clean the path to remove double slashes
	listenPath = path.Clean(listenPath)

	// Check if host already has a protocol (e.g., from edge endpoints)
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host + listenPath
	}

	return protocol + host + listenPath
}

// buildVersionedServerURL constructs a server URL for a versioned API
// based on the versioning method (URL path, query param, or header).
func buildVersionedServerURL(
	protocol, host, listenPath string,
	versionLocation, versionKey, versionName string,
) (string, string) {
	baseURL := buildServerURL(protocol, host, listenPath)
	var description string

	switch versionLocation {
	case "url":
		fallthrough
	default:
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}
		baseURL += versionName

	case "url-param":
		baseURL += "?" + versionKey + "=" + versionName

	case "header":
		return baseURL, description
	}

	return baseURL, description
}

// removeTykGeneratedURLs removes Tyk-generated server URLs from the servers list.
// It uses URL normalization for robust matching and preserves all other servers.
func removeTykGeneratedURLs(servers openapi3.Servers, tykURLs []string) openapi3.Servers {
	if len(servers) == 0 || len(tykURLs) == 0 {
		return servers
	}

	// Build a map of normalized Tyk URLs for fast lookup
	tykURLMap := make(map[string]bool, len(tykURLs))
	for _, tykURL := range tykURLs {
		normalized := normalizeServerURL(tykURL)
		tykURLMap[normalized] = true
	}

	// Keep only servers that aren't in the Tyk URL list
	userServers := make(openapi3.Servers, 0, len(servers))
	for _, server := range servers {
		normalized := normalizeServerURL(server.URL)
		if !tykURLMap[normalized] {
			userServers = append(userServers, server)
		}
	}

	return userServers
}

// normalizeServerURL normalizes a server URL for comparison.
// This handles trailing slashes, double slashes, and other URL inconsistencies.
func normalizeServerURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// If we can't parse it, try basic string normalization
		return strings.TrimSuffix(rawURL, "/")
	}

	// Clean and normalize the path
	u.Path = strings.TrimSuffix(path.Clean(u.Path), "/")
	if u.Path == "" || u.Path == "." {
		u.Path = "/"
	}

	return u.String()
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ShouldUpdateChildAPIs checks if child APIs need server updates after a base API change.
//
// Configuration changes that trigger child API updates:
// - Versioning method changed (url/url-param/header)
// - Versioning key changed (parameter/header name)
// - Base API's listen path changed
// - FallbackToDefault setting changed (affects fallback URL generation)
// - Default version changed (affects which child is the default)
func ShouldUpdateChildAPIs(newAPI, oldAPI *apidef.APIDefinition) bool {
	if newAPI == nil {
		return false
	}

	if !newAPI.IsBaseAPI() {
		return false
	}

	// If oldAPI is nil, this is a new API, no children exist yet
	if oldAPI == nil {
		return false
	}

	// 1. Versioning method changed (url/url-param/header)
	if oldAPI.VersionDefinition.Location != newAPI.VersionDefinition.Location {
		return true
	}

	// 2. Versioning key changed (parameter/header name)
	if oldAPI.VersionDefinition.Key != newAPI.VersionDefinition.Key {
		return true
	}

	// 3. Base API's listen path changed (child versioned URLs use base's path)
	if oldAPI.Proxy.ListenPath != newAPI.Proxy.ListenPath {
		return true
	}

	// 4. FallbackToDefault changed - affects which child APIs get fallback URLs
	if oldAPI.VersionDefinition.FallbackToDefault != newAPI.VersionDefinition.FallbackToDefault {
		return true
	}

	// 5. Default version changed - affects which child API is the "default"
	if oldAPI.VersionDefinition.Default != newAPI.VersionDefinition.Default {
		return true
	}

	return false
}

// ExtractUserServers extracts user provided servers from an existing OAS API
// by regenerating what the Tyk servers should be and filtering them out.
func ExtractUserServers(
	existingServers openapi3.Servers,
	apiDef *apidef.APIDefinition,
	baseAPI *apidef.APIDefinition,
	config ServerRegenerationConfig,
	versionName string,
) (openapi3.Servers, error) {
	if len(existingServers) == 0 {
		return openapi3.Servers{}, nil
	}

	tempOAS := &OAS{T: openapi3.T{Servers: openapi3.Servers{}}}

	err := tempOAS.RegenerateServers(apiDef, nil, baseAPI, nil, config, versionName)
	if err != nil {
		return nil, fmt.Errorf("failed to regenerate servers for user server extraction: %w", err)
	}

	// Build a map of normalized Tyk URLs for fast lookup
	tykURLMap := make(map[string]bool, len(tempOAS.Servers))
	for _, server := range tempOAS.Servers {
		normalized := normalizeServerURL(server.URL)
		tykURLMap[normalized] = true
	}

	// Filter existing servers to keep only user provided ones and not Tyk generated
	userServers := make(openapi3.Servers, 0, len(existingServers))
	for _, server := range existingServers {
		normalized := normalizeServerURL(server.URL)
		if !tykURLMap[normalized] {
			userServers = append(userServers, server)
		}
	}

	return userServers, nil
}
