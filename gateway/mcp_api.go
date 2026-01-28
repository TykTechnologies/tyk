package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/mcp"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/sanitize"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
)

const errMsgDeleteFailed = "Delete failed"

// extractMCPObjFromReq extracts and parses MCP API definition from request body.
func extractMCPObjFromReq(reqBody io.Reader) ([]byte, *oas.OAS, error) {
	var mcpObj oas.OAS
	reqBodyInBytes, err := ioutil.ReadAll(reqBody)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	loader := openapi3.NewLoader()
	t, err := loader.LoadFromData(reqBodyInBytes)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	mcpObj.T = *t

	return reqBodyInBytes, &mcpObj, nil
}

func (gw *Gateway) validateMCP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqBodyInBytes, mcpObj, err := extractMCPObjFromReq(r.Body)

		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && mcpObj.GetTykExtension() == nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrPayloadWithoutTykExtension.Error()))
			return
		}

		if err = mcp.ValidateMCPObject(reqBodyInBytes, mcpObj.OpenAPI); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if err = mcpObj.Validate(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

func (gw *Gateway) handleAddMCP(r *http.Request, fs afero.Fs) (interface{}, int) {
	var (
		newDef apidef.APIDefinition
		oasObj oas.OAS
	)

	versionParams := lib.NewVersionQueryParameters(r.URL.Query())
	err := versionParams.Validate(func() (bool, string) {
		baseApiID := versionParams.Get(lib.BaseAPIID)
		baseApi := gw.getApiSpec(baseApiID)
		if baseApi != nil {
			return true, baseApi.VersionDefinition.Name
		}
		return false, ""
	})

	if err != nil {
		if errors.Is(err, lib.ErrNewVersionRequired) {
			return apiError(err.Error()), http.StatusUnprocessableEntity
		}
		return apiError(err.Error()), http.StatusBadRequest
	}

	if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
		log.Error("Couldn't decode MCP OAS object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	oasObj.ExtractTo(&newDef)
	newDef.MarkAsMCP()

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if errResp, errCode := ensureAndValidateAPIID(&newDef); errResp != nil {
		return errResp, errCode
	}

	versioningParams := extractVersioningParams(
		versionParams.Get(lib.BaseAPIID),
		versionParams.Get(lib.NewVersionName),
	)

	if err := gw.handleOASServersForNewAPI(&newDef, &oasObj, versioningParams); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true
	oasObj.GetTykExtension().Info.ID = newDef.APIID
	err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	if !versionParams.IsEmpty(lib.BaseAPIID) {
		baseAPIID := versionParams.Get(lib.BaseAPIID)
		if err := gw.updateBaseAPIWithNewVersion(baseAPIID, versionParams, newDef.APIID, fs); err != nil {
			log.WithError(err).Error("Failed to update base API")
			return apiError("Failed to update base API"), http.StatusInternalServerError
		}
	}

	return apiModifyKeySuccess{
		Key:    newDef.APIID,
		Status: "ok",
		Action: "added",
	}, http.StatusOK
}

func (gw *Gateway) handleUpdateMCP(apiID string, r *http.Request, fs afero.Fs) (interface{}, int) {
	var (
		newDef apidef.APIDefinition
		oasObj oas.OAS
	)

	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiID, err)
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if spec == nil {
		return apiError("API not found"), http.StatusNotFound
	}

	if !spec.IsMCP() {
		return apiError("API is not an MCP API"), http.StatusNotFound
	}

	if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
		log.Error("Couldn't decode MCP OAS object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	oasObj.ExtractTo(&newDef)
	newDef.MarkAsMCP()

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if apiID != "" && newDef.APIID != apiID {
		log.Error("PUT operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Update operations these must match."), http.StatusBadRequest
	}

	if err := gw.handleOASServersForUpdate(spec, &newDef, &oasObj); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true
	err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	return apiModifyKeySuccess{
		Key:    newDef.APIID,
		Status: "ok",
		Action: "modified",
	}, http.StatusOK
}

func (gw *Gateway) handleGetMCPListOAS() (interface{}, int) {
	return gw.handleGetOASList((*APISpec).IsMCP, false)
}

func (gw *Gateway) mcpListHandler(w http.ResponseWriter, _ *http.Request) {
	log.Debug("Requesting MCP list")
	obj, code := gw.handleGetMCPListOAS()
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleGetMCP(apiID string) (interface{}, int) {
	return gw.handleGetOASByID(apiID, mcpTypeCheck)
}

func (gw *Gateway) mcpGetHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Requesting MCP definition for %q", apiID)

	obj, code := gw.handleGetMCP(apiID)

	if code == http.StatusOK {
		if oasAPI, ok := obj.(*oas.OAS); ok {
			api := gw.getApiSpec(oasAPI.GetTykExtension().Info.ID)
			if api != nil && api.VersionDefinition.BaseID != "" {
				w.Header().Set(apidef.HeaderBaseAPIID, api.VersionDefinition.BaseID)
			}
		}
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) mcpCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Creating MCP API")
	obj, code := gw.handleAddMCP(r, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) mcpUpdateHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Updating MCP API: %q", apiID)
	obj, code := gw.handleUpdateMCP(apiID, r, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleDeleteMCP(apiID string, fs afero.Fs) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiID, err)
		return apiStatusMessage{Status: "error", Message: "Invalid API ID"}, http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if spec == nil {
		return apiStatusMessage{Status: "error", Message: "API not found"}, http.StatusNotFound
	}

	if !spec.IsMCP() {
		return apiStatusMessage{Status: "error", Message: "API is not an MCP API"}, http.StatusNotFound
	}

	defFilePath := filepath.Join(gw.GetConfig().AppPath, apiID+".json")
	defFilePath = filepath.Clean(defFilePath)
	defMCPFilePath := filepath.Join(gw.GetConfig().AppPath, apiID+"-mcp.json")
	defMCPFilePath = filepath.Clean(defMCPFilePath)

	if _, err := fs.Stat(defFilePath); err != nil {
		log.Warning("File does not exist! ", err)
		return apiStatusMessage{Status: "error", Message: errMsgDeleteFailed}, http.StatusInternalServerError
	}

	if _, err := fs.Stat(defMCPFilePath); err != nil {
		log.Warning("MCP file does not exist! ", err)
		return apiStatusMessage{Status: "error", Message: errMsgDeleteFailed}, http.StatusInternalServerError
	}

	if err := fs.Remove(defFilePath); err != nil {
		log.WithError(err).Errorf("Failed to delete API file: %s", defFilePath)
		return apiStatusMessage{Status: "error", Message: errMsgDeleteFailed}, http.StatusInternalServerError
	}
	if err := fs.Remove(defMCPFilePath); err != nil {
		log.WithError(err).Errorf("Failed to delete MCP file: %s", defMCPFilePath)
		return apiStatusMessage{Status: "error", Message: errMsgDeleteFailed}, http.StatusInternalServerError
	}

	if spec.VersionDefinition.BaseID != "" {
		if err := gw.removeAPIFromBaseVersion(apiID, spec.VersionDefinition.BaseID, fs); err != nil {
			log.WithError(err).Error("Failed to update base API after delete")
			// Don't fail the delete operation if base API update fails
		}
	}

	response := apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: "deleted",
	}

	return response, http.StatusOK
}

func (gw *Gateway) mcpDeleteHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Deleting MCP API: %q", apiID)
	obj, code := gw.handleDeleteMCP(apiID, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}
