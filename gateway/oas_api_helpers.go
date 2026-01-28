package gateway

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/sanitize"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
)

type apiFilterFunc func(*APISpec) bool

type apiTypeCheck func(*APISpec) error

func isOASNotMCP(spec *APISpec) bool {
	return spec.IsOAS && !spec.IsMCP()
}

func typeCheckFunc(name string, predicate apiFilterFunc) apiTypeCheck {
	return func(spec *APISpec) error {
		if !predicate(spec) {
			return errors.New("API is not an " + name + " API")
		}
		return nil
	}
}

var (
	mcpTypeCheck = typeCheckFunc("MCP", (*APISpec).IsMCP)
)

// ensureAndValidateAPIID generates an API ID if empty and validates it.
func ensureAndValidateAPIID(apiDef *apidef.APIDefinition) (interface{}, int) {
	if apiDef.APIID == "" {
		apiDef.GenerateAPIID()
	}

	if err := sanitize.ValidatePathComponent(apiDef.APIID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiDef.APIID, err)
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	return nil, 0
}

// handleGetOASList returns OAS APIs matching the filter predicate.
// Thread-safe: acquires read lock.
func (gw *Gateway) handleGetOASList(filter apiFilterFunc, modePublic bool) (interface{}, int) {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	apisList := []oas.OAS{}

	for _, apiSpec := range gw.apisByID {
		if filter(apiSpec) {
			apiSpec.OAS.Fill(*apiSpec.APIDefinition)
			if modePublic {
				apiSpec.OAS.RemoveTykExtension()
			}
			apisList = append(apisList, apiSpec.OAS)
		}
	}

	return apisList, http.StatusOK
}

func (gw *Gateway) handleGetOASByID(apiID string, typeCheck apiTypeCheck) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiID, err)
		return apiStatusMessage{Status: "error", Message: "Invalid API ID"}, http.StatusBadRequest
	}

	api := gw.getApiSpec(apiID)
	if api == nil {
		return apiStatusMessage{Status: "error", Message: "API not found"}, http.StatusNotFound
	}

	if err := typeCheck(api); err != nil {
		return apiStatusMessage{Status: "error", Message: err.Error()}, http.StatusNotFound
	}

	api.OAS.Fill(*api.APIDefinition)
	return &api.OAS, http.StatusOK
}

// copyAPIDefForPersistence creates a deep copy of an APIDefinition for safe I/O outside locks.
func copyAPIDefForPersistence(apiDef *apidef.APIDefinition) (*apidef.APIDefinition, error) {
	data, err := json.Marshal(apiDef)
	if err != nil {
		return nil, err
	}

	var copy apidef.APIDefinition
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}

	return &copy, nil
}

// copyOASForPersistence creates a deep copy of an OAS object for safe I/O outside locks.
func copyOASForPersistence(oasObj *oas.OAS) (*oas.OAS, error) {
	data, err := json.Marshal(oasObj)
	if err != nil {
		return nil, err
	}

	var copy oas.OAS
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}

	return &copy, nil
}

// updateBaseAPIWithNewVersion updates a base API's version definition when adding a new versioned child API.
// Minimizes lock duration by performing file I/O outside the lock.
func (gw *Gateway) updateBaseAPIWithNewVersion(
	baseAPIID string,
	versionParams *lib.VersionQueryParameters,
	newAPIID string,
	fs afero.Fs,
) error {
	gw.apisMu.Lock()

	baseAPI := gw.apisByID[baseAPIID]
	if baseAPI == nil {
		gw.apisMu.Unlock()
		log.Errorf("Base API %q not found", baseAPIID)
		return errors.New("base API not found")
	}

	oldDefaultVersion := baseAPI.VersionDefinition.Default
	baseAPI.VersionDefinition = lib.ConfigureVersionDefinition(baseAPI.VersionDefinition, versionParams, newAPIID)

	if baseAPI.IsOAS {
		baseAPI.OAS.Fill(*baseAPI.APIDefinition)
	}

	apiDefCopy, copyErr := copyAPIDefForPersistence(baseAPI.APIDefinition)
	var oasCopy *oas.OAS
	if baseAPI.IsOAS && copyErr == nil {
		oasCopy, copyErr = copyOASForPersistence(&baseAPI.OAS)
	}

	isOAS := baseAPI.IsOAS
	apiID := baseAPI.APIID
	newDefaultVersion := baseAPI.VersionDefinition.Default

	gw.apisMu.Unlock()

	if copyErr != nil {
		log.WithError(copyErr).Errorf("Failed to copy base API for persistence: %s", apiID)
		return copyErr
	}

	if isOAS {
		err, _ := gw.writeOASAndAPIDefToFile(fs, apiDefCopy, oasCopy)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base OAS API with id: %s", apiID)
		}
	} else {
		err, _ := gw.writeToFile(fs, apiDefCopy, apiID)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base API with id: %s", apiID)
		}
	}

	setDefault := !versionParams.IsEmpty(lib.SetDefault) && versionParams.Get(lib.SetDefault) == "true"
	if oas.ShouldUpdateOldDefaultChild(setDefault, oldDefaultVersion, newDefaultVersion) {
		gw.apisMu.RLock()
		baseAPI = gw.apisByID[baseAPIID]
		gw.apisMu.RUnlock()

		if baseAPI != nil {
			if err := gw.updateOldDefaultChildServersGW(oldDefaultVersion, baseAPI, fs); err != nil {
				log.WithError(err).Warn("Failed to update old default child API servers")
			}
		}
	}

	return nil
}

// removeAPIFromBaseVersion removes a deleted API from its base API's version list.
// Minimizes lock duration by performing file I/O outside the lock.
func (gw *Gateway) removeAPIFromBaseVersion(apiID string, baseAPIID string, fs afero.Fs) error {
	gw.apisMu.Lock()

	baseAPI := gw.apisByID[baseAPIID]
	if baseAPI == nil {
		gw.apisMu.Unlock()
		log.Errorf("Base API %q not found", baseAPIID)
		return errors.New("base API not found")
	}

	for versionName, versionAPIID := range baseAPI.VersionDefinition.Versions {
		if apiID == versionAPIID {
			delete(baseAPI.VersionDefinition.Versions, versionName)
			if baseAPI.VersionDefinition.Default == versionName {
				baseAPI.VersionDefinition.Default = baseAPI.VersionDefinition.Name
			}
			break
		}
	}

	if baseAPI.IsOAS {
		baseAPI.OAS.Fill(*baseAPI.APIDefinition)
	}

	apiDefCopy, copyErr := copyAPIDefForPersistence(baseAPI.APIDefinition)
	var oasCopy *oas.OAS
	if baseAPI.IsOAS && copyErr == nil {
		oasCopy, copyErr = copyOASForPersistence(&baseAPI.OAS)
	}

	isOAS := baseAPI.IsOAS
	apiIDStr := baseAPI.APIID

	gw.apisMu.Unlock()

	if copyErr != nil {
		log.WithError(copyErr).Errorf("Failed to copy base API for persistence: %s", apiIDStr)
		return copyErr
	}

	if isOAS {
		err, _ := gw.writeOASAndAPIDefToFile(fs, apiDefCopy, oasCopy)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base OAS API with id: %s", apiIDStr)
			return err
		}
	} else {
		err, _ := gw.writeToFile(fs, apiDefCopy, apiIDStr)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base API with id: %s", apiIDStr)
			return err
		}
	}

	return nil
}
