package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/mcp"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/sanitize"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
)

const errMsgDeleteFailed = "Delete failed"

// extractMCPObjFromReq extracts and parses MCP Proxy definition from request body.
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

type mcpProxyDefinition struct {
	apiDef apidef.APIDefinition
	oasObj oas.OAS
}

func decodeMCPProxyDefinition(reqBody io.Reader) (*mcpProxyDefinition, error) {
	var parsed mcpProxyDefinition
	if err := json.NewDecoder(reqBody).Decode(&parsed.oasObj); err != nil {
		log.Error("Couldn't decode MCP OAS object: ", err)
		return nil, ErrRequestMalformed
	}

	parsed.oasObj.ExtractTo(&parsed.apiDef)
	if !parsed.apiDef.IsPairedMCPAdapterProxy() {
		parsed.apiDef.MarkAsMCP()
	}
	return &parsed, nil
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

		// MCP-aware validate: PRM is checked with isMCP=true so the
		// empty-mode + no-resource shape resolves to mirror (auto) rather
		// than static-with-missing-resource. This lets users enable PRM
		// on a remote MCP API with a single `enabled: true` line.
		if err = mcpObj.ValidateForMCP(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if errMsg, errCode := gw.validatePairedMCPAdapterUpstream(r, mcpObj); errMsg != "" {
			doJSONWrite(w, errCode, apiError(errMsg))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

func pairedMCPAdapterTarget(target string) (adapterID, restAPIID string, ok bool) {
	return oas.ParseAdapterTarget(strings.TrimSpace(target))
}

func (gw *Gateway) validatePairedMCPAdapterUpstream(_ *http.Request, mcpObj *oas.OAS) (string, int) {
	if mcpObj == nil || mcpObj.GetTykExtension() == nil {
		return "", 0
	}

	var incoming apidef.APIDefinition
	mcpObj.ExtractTo(&incoming)

	_, restAPIID, ok := pairedMCPAdapterTarget(incoming.Proxy.TargetURL)
	if !ok {
		return "", 0
	}

	gw.apisMu.RLock()
	rest := gw.apisByID[restAPIID]
	gw.apisMu.RUnlock()

	if rest == nil || rest.APIDefinition == nil {
		return "Paired REST API " + restAPIID + " is not loaded; create it first", http.StatusBadRequest
	}
	if rest.OrgID != incoming.OrgID {
		return "Paired REST API belongs to a different OrgID", http.StatusForbidden
	}
	if !rest.IsOAS {
		return "Paired REST API " + restAPIID + " is a Classic API; REST-as-MCP sources must be Tyk OAS APIs", http.StatusBadRequest
	}

	view, warnings, err := oas.DeriveMCPToolView(&rest.OAS, mcpObj.GetTykMCPServerExtension())
	logMCPDeriveWarnings(incoming.APIID, restAPIID, warnings)
	if err != nil {
		return err.Error(), http.StatusBadRequest
	}
	if err := gw.validateMCPToolViewAliasConflicts(incoming.APIID, incoming.OrgID, restAPIID, view); err != nil {
		return err.Error(), http.StatusBadRequest
	}

	return "", 0
}

func (gw *Gateway) validateMCPToolViewAliasConflicts(incomingProxyAPIID, orgID, restAPIID string, incomingView oas.MCPToolView) error {
	incomingByName := mcpToolViewSourceIDsByName(incomingView)
	if len(incomingByName) == 0 {
		return nil
	}

	rest, proxies := gw.mcpToolViewAliasConflictCandidates(incomingProxyAPIID, orgID, restAPIID)
	if rest == nil {
		return nil
	}

	sort.Slice(proxies, func(i, j int) bool { return proxies[i].APIID < proxies[j].APIID })
	for _, spec := range proxies {
		if err := validateMCPToolViewAliasConflictAgainstProxy(rest, spec, restAPIID, incomingByName); err != nil {
			return err
		}
	}

	return nil
}

func (gw *Gateway) mcpToolViewAliasConflictCandidates(incomingProxyAPIID, orgID, restAPIID string) (*APISpec, []*APISpec) {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	rest := gw.apisByID[restAPIID]
	proxies := make([]*APISpec, 0)
	for _, spec := range gw.apisByID {
		if !isMCPToolViewAliasConflictCandidate(spec, incomingProxyAPIID, orgID, restAPIID) {
			continue
		}
		proxies = append(proxies, spec)
	}

	return rest, proxies
}

func isMCPToolViewAliasConflictCandidate(spec *APISpec, incomingProxyAPIID, orgID, restAPIID string) bool {
	if spec == nil || spec.APIDefinition == nil || spec.APIID == incomingProxyAPIID || !spec.IsMCPManaged() {
		return false
	}

	_, sourceRESTAPIID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
	return ok && sourceRESTAPIID == restAPIID && spec.OrgID == orgID
}

func validateMCPToolViewAliasConflictAgainstProxy(rest, spec *APISpec, restAPIID string, incomingByName map[string]string) error {
	existingView, warnings, err := oas.DeriveMCPToolView(&rest.OAS, spec.OAS.GetTykMCPServerExtension())
	logMCPDeriveWarnings(spec.APIID, restAPIID, warnings)
	if err != nil {
		return fmt.Errorf("build MCP tool view for existing proxy %q: %w", spec.APIID, err)
	}

	return mcpToolViewAliasConflict(spec.APIID, incomingByName, mcpToolViewSourceIDsByName(existingView))
}

func mcpToolViewAliasConflict(proxyAPIID string, incomingByName, existingByName map[string]string) error {
	for name, incomingSourceID := range incomingByName {
		existingSourceID, ok := existingByName[name]
		if !ok || existingSourceID == incomingSourceID {
			continue
		}
		return fmt.Errorf("MCP tool alias conflict for %q: incoming proxy maps to source %q, proxy %q maps to source %q", name, incomingSourceID, proxyAPIID, existingSourceID)
	}
	return nil
}

func logMCPDeriveWarnings(proxyAPIID, restAPIID string, warnings []oas.DeriveWarning) {
	for _, warning := range warnings {
		log.WithFields(logrus.Fields{
			"api_id":      proxyAPIID,
			"rest_api_id": restAPIID,
			"operation":   warning.Operation,
			"method":      warning.Method,
			"path":        warning.Path,
			"reason":      warning.Reason,
		}).Warn("REST-as-MCP derivation warning")
	}
}

func mcpToolViewSourceIDsByName(view oas.MCPToolView) map[string]string {
	out := make(map[string]string, len(view.Tools))
	for _, tool := range view.Tools {
		out[tool.Name] = derivedToolSourceIdentity(tool)
	}
	return out
}

func derivedToolSourceIdentity(tool oas.DerivedTool) string {
	if tool.SourceKey != "" {
		return tool.SourceKey
	}
	if tool.OperationID != "" {
		return "operationId:" + tool.OperationID
	}
	if tool.Method != "" && tool.PathTemplate != "" {
		return "http:" + strings.ToUpper(strings.TrimSpace(tool.Method)) + " " + strings.TrimSpace(tool.PathTemplate)
	}
	return tool.CanonicalName
}

func (gw *Gateway) handleAddMCP(r *http.Request, fs afero.Fs) (interface{}, int) {
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

	parsed, err := decodeMCPProxyDefinition(r.Body)
	if err != nil {
		return apiError("Request malformed"), http.StatusBadRequest
	}
	newDef := &parsed.apiDef
	oasObj := &parsed.oasObj

	if validationErr := validateAPIDef(newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if errResp, errCode := ensureAndValidateAPIID(newDef); errResp != nil {
		return errResp, errCode
	}

	versioningParams := extractVersioningParams(
		versionParams.Get(lib.BaseAPIID),
		versionParams.Get(lib.NewVersionName),
	)

	if err := gw.handleOASServersForNewAPI(newDef, oasObj, versioningParams); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true
	oasObj.GetTykExtension().Info.ID = newDef.APIID
	err, errCode := gw.writeOASAndAPIDefToFile(fs, newDef, oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	if resp, code := handleBaseVersionUpdate(gw, versionParams, newDef.APIID, fs); resp != nil {
		return resp, code
	}

	return buildSuccessResponse(newDef.APIID, "added")
}

func (gw *Gateway) handleUpdateMCP(apiID string, r *http.Request, fs afero.Fs) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiID, err)
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
	}

	if !spec.IsMCPManaged() {
		return apiError("API is not an MCP Proxy"), http.StatusNotFound
	}

	parsed, err := decodeMCPProxyDefinition(r.Body)
	if err != nil {
		return apiError("Request malformed"), http.StatusBadRequest
	}
	newDef := &parsed.apiDef
	oasObj := &parsed.oasObj

	if validationErr := validateAPIDef(newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if resp, code := validateAPIIDMatch(apiID, newDef.APIID); resp != nil {
		return resp, code
	}

	if err := gw.handleOASServersForUpdate(spec, newDef, oasObj); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true
	err, errCode := gw.writeOASAndAPIDefToFile(fs, newDef, oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	return buildSuccessResponse(newDef.APIID, "modified")
}

func (gw *Gateway) handleGetMCPListOAS() (interface{}, int) {
	return gw.handleGetOASList(mcpProxy, false)
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
	log.Debug("Creating MCP Proxy")
	obj, code := gw.handleAddMCP(r, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) mcpUpdateHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Updating MCP Proxy: %q", apiID)
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

	if !spec.IsMCPManaged() {
		return apiError("API is not an MCP Proxy"), http.StatusNotFound
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
	log.Debugf("Deleting MCP Proxy: %q", apiID)
	obj, code := gw.handleDeleteMCP(apiID, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}
