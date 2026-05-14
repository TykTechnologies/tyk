package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"strings"

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

		// REST-as-MCP: when the proxy's upstream points at a synthetic
		// adapter, verify the pairing is safe before accepting the
		// proxy into storage. These checks are belt-and-braces with the
		// runtime check in MCPLoopAuthBypass.
		if errMsg, errCode := gw.validatePairedMCPAdapterUpstream(r, mcpObj); errMsg != "" {
			doJSONWrite(w, errCode, apiError(errMsg))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

func pairedMCPAdapterTarget(target string) (adapterID, restAPIID string, ok bool) {
	u, err := neturl.Parse(strings.TrimSpace(target))
	if err != nil || u.Scheme != "tyk" {
		return "", "", false
	}

	adapterID = strings.TrimPrefix(u.Host, "id:")
	if !oas.IsAdapterAPIID(adapterID) {
		return "", "", false
	}

	return adapterID, oas.AdapterSourceAPIID(adapterID), true
}

// validatePairedMCPAdapterUpstream enforces REST-as-MCP admit-time
// invariants when an MCP proxy targets a synthetic adapter via a
// `tyk://<adapterAPIID>` upstream URL. Returns ("", 0) when the upstream
// does not address an adapter (and is therefore out of scope here).
//
// Checks:
//
//  1. The named REST APISpec exists in apisByID.
//  2. That REST spec has `server.mcp.enabled: true`.
//  3. The REST spec and the incoming proxy share an OrgID.
//  4. No other admitted proxy already targets the same adapter (1:1).
func (gw *Gateway) validatePairedMCPAdapterUpstream(r *http.Request, mcpObj *oas.OAS) (string, int) {
	if mcpObj == nil {
		return "", 0
	}
	ext := mcpObj.GetTykExtension()
	if ext == nil {
		return "", 0
	}

	// Only OAS-described upstream is the operator-managed proxy's
	// `upstream.url`; pull it from the underlying apidef shape.
	var temp apidef.APIDefinition
	mcpObj.ExtractTo(&temp)
	target := temp.Proxy.TargetURL
	if target == "" {
		return "", 0
	}
	_, restAPIID, ok := pairedMCPAdapterTarget(target)
	if !ok {
		return "", 0
	}

	gw.apisMu.RLock()
	rest, ok := gw.apisByID[restAPIID]
	gw.apisMu.RUnlock()
	pairingClone := gw.mcpPairing.PairingSnapshot()

	if !ok || rest == nil || rest.APIDefinition == nil {
		return "Paired REST API " + restAPIID + " is not loaded; create it first", http.StatusBadRequest
	}
	if !rest.IsMCPExposed() {
		return "Paired REST API " + restAPIID + " is not marked server.mcp.enabled=true", http.StatusBadRequest
	}
	if rest.OrgID != temp.OrgID {
		return "Paired REST API belongs to a different OrgID", http.StatusForbidden
	}

	// 1:1 invariant — reject if another proxy already targets this
	// adapter, unless the request is updating the same proxy that
	// already holds the pairing.
	if existing, paired := pairingClone[restAPIID]; paired && existing != temp.APIID {
		return "Paired REST API is already exposed by MCP proxy " + existing, http.StatusConflict
	}

	_ = r // r is only used for context elsewhere; keep parameter for future audit-logging.
	return "", 0
}

func (gw *Gateway) alignPairedMCPProxyGatewayTags(apiDef *apidef.APIDefinition, oasObj *oas.OAS) error {
	if apiDef == nil || oasObj == nil {
		return nil
	}

	_, restAPIID, ok := pairedMCPAdapterTarget(apiDef.Proxy.TargetURL)
	if !ok {
		return nil
	}

	rest := gw.getApiSpec(restAPIID)
	if rest == nil || rest.APIDefinition == nil {
		return fmt.Errorf("paired REST API %s is not loaded; create it first", restAPIID)
	}

	apiDef.TagsDisabled = rest.TagsDisabled
	apiDef.Tags = append([]string(nil), rest.Tags...)

	ext := oasObj.GetTykExtension()
	if ext == nil {
		return nil
	}
	if ext.Server.GatewayTags == nil {
		ext.Server.GatewayTags = &oas.GatewayTags{}
	}
	ext.Server.GatewayTags.Enabled = !apiDef.TagsDisabled
	ext.Server.GatewayTags.Tags = append([]string(nil), apiDef.Tags...)

	return nil
}

func (gw *Gateway) pairedMCPProxyForREST(restAPIID string) (string, bool) {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	for _, spec := range gw.apisByID {
		if spec == nil || spec.APIDefinition == nil || !spec.IsMCPManaged() || spec.IsSyntheticMCPAdapter {
			continue
		}
		_, sourceRESTAPIID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
		if ok && sourceRESTAPIID == restAPIID {
			return spec.APIID, true
		}
	}

	return "", false
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
	// Only mark as MCP (which wires the JSON-RPC middleware on this
	// spec) when this is a classic remote-MCP proxy. REST-as-MCP
	// proxies are plain reverse-proxies whose upstream loops into a
	// synthetic adapter — the adapter owns the JSON-RPC chain, the
	// proxy is just an authenticated/rate-limited forwarder.
	if !newDef.IsPairedMCPAdapterProxy() {
		newDef.MarkAsMCP()
	}

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

	if err := gw.alignPairedMCPProxyGatewayTags(&newDef, &oasObj); err != nil {
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

	if !spec.IsMCPManaged() {
		return apiError("API is not an MCP Proxy"), http.StatusNotFound
	}

	if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
		log.Error("Couldn't decode MCP OAS object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	oasObj.ExtractTo(&newDef)
	// See handleAddMCP for the rationale.
	if !newDef.IsPairedMCPAdapterProxy() {
		newDef.MarkAsMCP()
	}

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if resp, code := validateAPIIDMatch(apiID, newDef.APIID); resp != nil {
		return resp, code
	}

	if err := gw.handleOASServersForUpdate(spec, &newDef, &oasObj); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	if err := gw.alignPairedMCPProxyGatewayTags(&newDef, &oasObj); err != nil {
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
	return gw.handleGetOASList(mcpManaged, false)
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
		if !spec.IsPairedMCPAdapterProxy() {
			log.Warning("Delete failed: ", err)
			return apiError(errMsgDeleteFailed), http.StatusInternalServerError
		}
		if err = deleteAPIFiles(apiID, "oas", gw.GetConfig().AppPath, fs); err != nil {
			log.Warning("Delete failed: ", err)
			return apiError(errMsgDeleteFailed), http.StatusInternalServerError
		}
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
