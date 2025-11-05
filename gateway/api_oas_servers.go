package gateway

import (
	"strconv"

	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

// buildServerRegenerationConfig creates a ServerRegenerationConfig from Gateway config.
func buildServerRegenerationConfig(conf config.Config) oas.ServerRegenerationConfig {
	protocol := "http://"
	if conf.HttpServerOptions.UseSSL {
		protocol = "https://"
	}

	defaultHost := conf.ListenAddress
	if conf.HostName != "" {
		defaultHost = conf.HostName
	}
	if defaultHost == "" {
		defaultHost = "127.0.0.1"
	}

	// Add port unless it's default (80 for http, 443 for https)
	if (protocol != "http://" || conf.ListenPort != 80) &&
		(protocol != "https://" || conf.ListenPort != 443) {
		defaultHost = defaultHost + ":" + strconv.Itoa(conf.ListenPort)
	}

	return oas.ServerRegenerationConfig{
		Protocol:      protocol,
		DefaultHost:   defaultHost,
		EdgeEndpoints: nil, // Gateway doesn't have edge endpoints
	}
}

// regenerateOASServers updates the servers section of an OAS API.
// This preserves user provided servers while correctly updating Tyk generated ones.
func (gw *Gateway) regenerateOASServers(
	spec *APISpec,
	apiDef *apidef.APIDefinition,
	oasObj *oas.OAS,
	baseAPI *APISpec,
	versionName string,
) error {
	serverConfig := buildServerRegenerationConfig(gw.GetConfig())

	var oldAPIData *apidef.APIDefinition
	if spec != nil {
		oldAPIData = spec.APIDefinition
	}

	var baseAPIData *apidef.APIDefinition
	var oldBaseAPIData *apidef.APIDefinition
	if baseAPI != nil {
		baseAPIData = baseAPI.APIDefinition
		oldBaseAPIData = baseAPI.APIDefinition
	}

	return oasObj.RegenerateServers(
		apiDef,
		oldAPIData,
		baseAPIData,
		oldBaseAPIData,
		serverConfig,
		versionName,
	)
}

// shouldUpdateChildAPIsGW checks if child APIs need server updates after base API changes.
// Returns true if this is a base API with versions and versioning config changed.
func (gw *Gateway) shouldUpdateChildAPIsGW(newBaseAPI, oldBaseAPI *apidef.APIDefinition) bool {
	return oas.ShouldUpdateChildAPIs(newBaseAPI, oldBaseAPI)
}

// updateChildAPIsServersGW updates server URLs for all child APIs when base API versioning changes.
// This is called after updating a base API if versioning configuration changed.
func (gw *Gateway) updateChildAPIsServersGW(newBaseAPISpec, oldBaseAPISpec *APISpec) error {
	newBaseAPI := newBaseAPISpec.APIDefinition
	oldBaseAPI := oldBaseAPISpec.APIDefinition

	if len(newBaseAPI.VersionDefinition.Versions) == 0 {
		return nil
	}

	log.Infof("Updating server URLs for %d child APIs of base API %s",
		len(newBaseAPI.VersionDefinition.Versions), newBaseAPI.APIID)

	serverConfig := buildServerRegenerationConfig(gw.GetConfig())

	for versionName, childAPIID := range newBaseAPI.VersionDefinition.Versions {
		if childAPIID == newBaseAPI.APIID {
			continue
		}

		childSpec := gw.getApiSpec(childAPIID)
		if childSpec == nil {
			log.Warnf("Child API %s (version %s) not found in loaded APIs", childAPIID, versionName)
			continue
		}

		if !childSpec.IsOAS {
			log.Debugf("Skipping non-OAS child API %s", childAPIID)
			continue
		}

		// Regenerate child's servers with new base API configuration
		err := childSpec.OAS.RegenerateServers(
			childSpec.APIDefinition,
			childSpec.APIDefinition,
			newBaseAPI,
			oldBaseAPI,
			serverConfig,
			versionName,
		)
		if err != nil {
			log.WithError(err).Warnf("Failed to update servers for child API %s", childAPIID)
			continue
		}

		childSpec.OAS.Fill(*childSpec.APIDefinition)

		log.Debugf("Successfully updated servers for child API %s (version %s)", childAPIID, versionName)
	}

	return nil
}

// updateOldDefaultChildServersGW updates the server URLs for the old default child API
// when a new version is set as default. This removes the fallback URL from the old default
// since it's no longer the default version.
func (gw *Gateway) updateOldDefaultChildServersGW(
	oldDefaultVersion string,
	baseAPISpec *APISpec,
	fs afero.Fs,
) error {
	baseAPI := baseAPISpec.APIDefinition

	// Find the old default child's API ID
	oldDefaultChildID, found := baseAPI.VersionDefinition.Versions[oldDefaultVersion]
	if !found {
		log.Warnf("Old default version %s not found in base API %s versions map",
			oldDefaultVersion, baseAPI.APIID)
		return nil // Non-fatal: version might have been deleted
	}

	// Skip if this is the base API itself
	if oldDefaultChildID == baseAPI.APIID {
		return nil
	}

	log.Infof("Updating servers for old default child API %s (version %s) of base API %s",
		oldDefaultChildID, oldDefaultVersion, baseAPI.APIID)

	// Fetch the old default child API from loaded specs
	childSpec := gw.getApiSpec(oldDefaultChildID)
	if childSpec == nil {
		log.Warnf("Old default child API %s not found in loaded APIs", oldDefaultChildID)
		return nil // Non-fatal: API might not be loaded yet
	}

	// Only update if child is an OAS API
	if !childSpec.IsOAS {
		log.Debugf("Skipping non-OAS old default child API %s", oldDefaultChildID)
		return nil
	}

	serverConfig := buildServerRegenerationConfig(gw.GetConfig())

	// Create a temporary base API with the OLD Default value for correct old URL computation
	oldBaseAPIState := *baseAPI
	oldBaseAPIState.VersionDefinition.Default = oldDefaultVersion

	// Regenerate servers with the updated base API state (new Default value)
	// This will cause shouldAddFallbackURL to return false for the old default
	err := childSpec.OAS.RegenerateServers(
		childSpec.APIDefinition,
		childSpec.APIDefinition,
		baseAPI,
		&oldBaseAPIState,
		serverConfig,
		oldDefaultVersion,
	)
	if err != nil {
		log.WithError(err).Warnf("Failed to regenerate servers for old default child API %s", oldDefaultChildID)
		return err
	}

	childSpec.OAS.Fill(*childSpec.APIDefinition)

	// Write the updated child API to filesystem
	err, _ = gw.writeToFile(fs, childSpec.APIDefinition, oldDefaultChildID)
	if err != nil {
		log.WithError(err).Warnf("Failed to save old default child API %s after updating servers", oldDefaultChildID)
		return err
	}

	log.Infof("Successfully updated servers for old default child API %s (version %s)",
		oldDefaultChildID, oldDefaultVersion)

	return nil
}

// versioningParams holds information about versioned API creation.
type versioningParams struct {
	// BaseAPIID is the ID of the base API (if this is a versioned child API)
	BaseAPIID string
	// VersionName is the name of the version being created
	VersionName string
}

// extractVersioningParams extracts versioning parameters from query string or returns empty if not versioned.
// This helper makes it easy to get versioning info for server regeneration.
func extractVersioningParams(baseAPIID, versionName string) versioningParams {
	return versioningParams{
		BaseAPIID:   baseAPIID,
		VersionName: versionName,
	}
}

// handleOASServersForNewAPI handles OAS server creation when adding a new API.
// It determines if this is a versioned child API and creates servers accordingly.
func (gw *Gateway) handleOASServersForNewAPI(
	apiDef *apidef.APIDefinition,
	oasObj *oas.OAS,
	versionParams versioningParams,
) error {
	var baseAPISpec *APISpec
	var versionName string

	if versionParams.BaseAPIID != "" {
		baseAPISpec = gw.getApiSpec(versionParams.BaseAPIID)
		versionName = versionParams.VersionName
	}

	return gw.regenerateOASServers(nil, apiDef, oasObj, baseAPISpec, versionName)
}

// handleOASServersForUpdate handles OAS server regeneration and cascade updates when updating an API.
// It regenerates servers for the updated API and triggers cascade updates to child APIs if needed.
func (gw *Gateway) handleOASServersForUpdate(
	oldSpec *APISpec,
	newAPIDef *apidef.APIDefinition,
	newOAS *oas.OAS,
) error {
	// Regenerate servers with old state for correct URL updates
	if err := gw.regenerateOASServers(oldSpec, newAPIDef, newOAS, nil, ""); err != nil {
		return err
	}

	// Check if child APIs need updating (if this is a base API with versioning changes)
	if gw.shouldUpdateChildAPIsGW(newAPIDef, oldSpec.APIDefinition) {
		// Create temp spec with new definition for cascade update
		newSpec := &APISpec{
			APIDefinition: newAPIDef,
			OAS:           *newOAS,
		}

		if err := gw.updateChildAPIsServersGW(newSpec, oldSpec); err != nil {
			log.WithError(err).Warn("Failed to update child APIs servers")
			// Don't fail the whole operation if child updates fail
		}
	}

	return nil
}
