package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"

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

	if resp, code := handleBaseVersionUpdate(gw, versionParams, newDef.APIID, fs); resp != nil {
		return resp, code
	}

	return buildSuccessResponse(newDef.APIID, "added")
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
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
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

	if resp, code := validateAPIIDMatch(apiID, newDef.APIID); resp != nil {
		return resp, code
	}

	if err := gw.handleOASServersForUpdate(spec, &newDef, &oasObj); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true
	err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	return buildSuccessResponse(newDef.APIID, "modified")
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
			gw.setBaseAPIIDHeader(w, oasAPI)
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
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
	}

	if !spec.IsMCP() {
		return apiError("API is not an MCP API"), http.StatusNotFound
	}

	if err := deleteAPIFiles(apiID, "mcp", gw.GetConfig().AppPath, fs); err != nil {
		log.Warning("Delete failed: ", err)
		return apiError(errMsgDeleteFailed), http.StatusInternalServerError
	}

	handleBaseVersionCleanup(gw, spec, apiID, fs)

	return buildSuccessResponse(apiID, "deleted")
}

func (gw *Gateway) mcpDeleteHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Deleting MCP API: %q", apiID)
	obj, code := gw.handleDeleteMCP(apiID, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}
