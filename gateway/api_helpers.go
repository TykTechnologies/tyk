package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

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
			return errors.New("API is not an " + name)
		}
		return nil
	}
}

var (
	mcpTypeCheck = typeCheckFunc("MCP Proxy", (*APISpec).IsMCP)
)

func (gw *Gateway) setBaseAPIIDHeader(w http.ResponseWriter, oasObj *oas.OAS) {
	if oasObj == nil {
		return
	}

	tykExt := oasObj.GetTykExtension()
	if tykExt == nil {
		return
	}

	api := gw.getApiSpec(tykExt.Info.ID)
	if api != nil && api.VersionDefinition.BaseID != "" {
		w.Header().Set(apidef.HeaderBaseAPIID, api.VersionDefinition.BaseID)
	}
}

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

func deleteAPIFiles(apiID, suffix, appPath string, fs afero.Fs) error {
	defFilePath := filepath.Join(appPath, apiID+".json")
	defFilePath = filepath.Clean(defFilePath)
	defOASFilePath := filepath.Join(appPath, apiID+"-"+suffix+".json")
	defOASFilePath = filepath.Clean(defOASFilePath)

	if _, err := fs.Stat(defFilePath); err != nil {
		return fmt.Errorf("main API definition file not found: %w", err)
	}

	if _, err := fs.Stat(defOASFilePath); err != nil {
		return fmt.Errorf("OAS file not found: %w", err)
	}

	if err := fs.Remove(defFilePath); err != nil {
		log.WithError(err).Errorf("Failed to delete API file: %s", defFilePath)
		return fmt.Errorf("failed to delete main API file: %w", err)
	}

	if err := fs.Remove(defOASFilePath); err != nil {
		log.WithError(err).Errorf("Failed to delete OAS file: %s", defOASFilePath)
		return fmt.Errorf("failed to delete OAS file: %w", err)
	}

	return nil
}

func validateSpecExists(spec *APISpec) (interface{}, int) {
	if spec == nil {
		return apiError(apidef.ErrAPINotFound.Error()), http.StatusNotFound
	}
	return nil, 0
}

func validateAPIIDMatch(pathAPIID, requestAPIID string) (interface{}, int) {
	if pathAPIID != "" && requestAPIID != pathAPIID {
		log.Error("PUT operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Update operations these must match."), http.StatusBadRequest
	}
	return nil, 0
}

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
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	api := gw.getApiSpec(apiID)
	if api == nil {
		return apiError("API not found"), http.StatusNotFound
	}

	if err := typeCheck(api); err != nil {
		return apiError(err.Error()), http.StatusNotFound
	}

	api.OAS.Fill(*api.APIDefinition)
	return &api.OAS, http.StatusOK
}

func deepCopyViaJSON[T any](src *T) (*T, error) {
	data, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}

	var copy T
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}

	return &copy, nil
}

func copyAPIDefForPersistence(apiDef *apidef.APIDefinition) (*apidef.APIDefinition, error) {
	return deepCopyViaJSON(apiDef)
}

func copyOASForPersistence(oasObj *oas.OAS) (*oas.OAS, error) {
	return deepCopyViaJSON(oasObj)
}

// copyBaseAPIForPersistence creates copies of the API definition and OAS (if applicable) for persistence.
// It returns the copies and any error encountered during the copy process.
func copyBaseAPIForPersistence(baseAPI *APISpec) (*apidef.APIDefinition, *oas.OAS, error) {
	apiDefCopy, err := copyAPIDefForPersistence(baseAPI.APIDefinition)
	if err != nil {
		return nil, nil, err
	}

	var oasCopy *oas.OAS
	if baseAPI.IsOAS {
		oasCopy, err = copyOASForPersistence(&baseAPI.OAS)
		if err != nil {
			return nil, nil, err
		}
	}

	return apiDefCopy, oasCopy, nil
}

// persistBaseAPI writes the base API to file, handling both OAS and non-OAS cases.
// updateOldDefaultIfNeeded updates the old default child API if needed based on version parameters.
func (gw *Gateway) updateOldDefaultIfNeeded(
	versionParams *lib.VersionQueryParameters,
	baseAPIID string,
	oldDefaultVersion string,
	newDefaultVersion string,
	fs afero.Fs,
) {
	setDefault := !versionParams.IsEmpty(lib.SetDefault) && versionParams.Get(lib.SetDefault) == "true"
	if !oas.ShouldUpdateOldDefaultChild(setDefault, oldDefaultVersion, newDefaultVersion) {
		return
	}

	gw.apisMu.RLock()
	baseAPI := gw.apisByID[baseAPIID]
	gw.apisMu.RUnlock()

	if baseAPI != nil {
		if err := gw.updateOldDefaultChildServersGW(oldDefaultVersion, baseAPI, fs); err != nil {
			log.WithError(err).Warn("Failed to update old default child API servers")
		}
	}
}

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

	apiDefCopy, oasCopy, copyErr := copyBaseAPIForPersistence(baseAPI)

	isOAS := baseAPI.IsOAS
	apiID := baseAPI.APIID
	newDefaultVersion := baseAPI.VersionDefinition.Default

	gw.apisMu.Unlock()

	if copyErr != nil {
		log.WithError(copyErr).Errorf("Failed to copy base API for persistence: %s", apiID)
		return copyErr
	}

	if err := gw.persistBaseAPIWithError(fs, apiDefCopy, oasCopy, isOAS, apiID); err != nil {
		return err
	}
	gw.updateOldDefaultIfNeeded(versionParams, baseAPIID, oldDefaultVersion, newDefaultVersion, fs)

	return nil
}

// removeVersionFromDefinition removes an API version from the version definition.
// If the removed version was the default, it resets the default to the base version name.
func removeVersionFromDefinition(versionDef *apidef.VersionDefinition, apiID string) {
	for versionName, versionAPIID := range versionDef.Versions {
		if apiID == versionAPIID {
			delete(versionDef.Versions, versionName)
			if versionDef.Default == versionName {
				versionDef.Default = versionDef.Name
			}
			break
		}
	}
}

// persistBaseAPIWithError writes the base API to file and returns any errors encountered.
func (gw *Gateway) persistBaseAPIWithError(fs afero.Fs, apiDefCopy *apidef.APIDefinition, oasCopy *oas.OAS, isOAS bool, apiID string) error {
	if isOAS {
		err, _ := gw.writeOASAndAPIDefToFile(fs, apiDefCopy, oasCopy)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base OAS API with id: %s", apiID)
			return err
		}
	} else {
		err, _ := gw.writeToFile(fs, apiDefCopy, apiID)
		if err != nil {
			log.WithError(err).Errorf("Error occurred while updating base API with id: %s", apiID)
			return err
		}
	}
	return nil
}

func (gw *Gateway) removeAPIFromBaseVersion(apiID string, baseAPIID string, fs afero.Fs) error {
	gw.apisMu.Lock()

	baseAPI := gw.apisByID[baseAPIID]
	if baseAPI == nil {
		gw.apisMu.Unlock()
		log.Errorf("Base API %q not found", baseAPIID)
		return errors.New("base API not found")
	}

	removeVersionFromDefinition(&baseAPI.VersionDefinition, apiID)

	if baseAPI.IsOAS {
		baseAPI.OAS.Fill(*baseAPI.APIDefinition)
	}

	apiDefCopy, oasCopy, copyErr := copyBaseAPIForPersistence(baseAPI)

	isOAS := baseAPI.IsOAS
	apiIDStr := baseAPI.APIID

	gw.apisMu.Unlock()

	if copyErr != nil {
		log.WithError(copyErr).Errorf("Failed to copy base API for persistence: %s", apiIDStr)
		return copyErr
	}

	return gw.persistBaseAPIWithError(fs, apiDefCopy, oasCopy, isOAS, apiIDStr)
}

func buildSuccessResponse(apiID, action string) (interface{}, int) {
	return apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: action,
	}, http.StatusOK
}

func handleBaseVersionCleanup(gw *Gateway, spec *APISpec, apiID string, fs afero.Fs) {
	if spec.VersionDefinition.BaseID != "" {
		if err := gw.removeAPIFromBaseVersion(apiID, spec.VersionDefinition.BaseID, fs); err != nil {
			log.WithError(err).Error("Failed to update base API after delete")
		}
	}
}

func handleBaseVersionUpdate(gw *Gateway, versionParams *lib.VersionQueryParameters, newAPIID string, fs afero.Fs) (interface{}, int) {
	if !versionParams.IsEmpty(lib.BaseAPIID) {
		baseAPIID := versionParams.Get(lib.BaseAPIID)
		if err := gw.updateBaseAPIWithNewVersion(baseAPIID, versionParams, newAPIID, fs); err != nil {
			log.WithError(err).Error("Failed to update base API")
			return apiError("Failed to update base API"), http.StatusInternalServerError
		}
	}
	return nil, 0
}
