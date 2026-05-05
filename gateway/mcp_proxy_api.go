package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/sanitize"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
)

// MCPProxy CRUD route surface.
//
// This file mirrors gateway/mcp_api.go (which serves the unrelated MCPPrimitive
// flow under /mcps). The /mcp-proxies surface defined here is the public-facing
// CRUD for the RFC-API-TO-MCP MCP Proxy (see RFC §12.1).
//
// Validation layers, in order:
//   1. Body parse + Tyk extension presence (mirrored from validateMCP).
//   2. Structural OAS validation, which already invokes (*MCPProxy).Validate
//      from apidef/oas/mcp_proxy.go (see oas.OAS.Validate). Failures surface
//      as 422 with the MCPProxyValidationError.Codes in the response body.
//   3. Runtime-state validation (mcp_proxy_validators.go in this package),
//      which inspects gw.apisHandlesByID and the loaded source APISpecs.
//      Failures surface as 409 with the full Violations punch list.
//
// Back-ref maintenance (RFC §12.2 step 4 / §12.4) is performed inline in the
// create/update/delete handlers below.

// mcpProxyValidationResponse is the 422 body returned for structural failures.
// It exposes the Codes slice from oas.MCPProxyValidationError so callers can
// pattern-match without parsing the message string.
type mcpProxyValidationResponse struct {
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Codes   []string `json:"codes,omitempty"`
	Details []string `json:"details,omitempty"`
}

// mcpProxyRuntimeResponse is the 409 body returned for runtime-state failures.
type mcpProxyRuntimeResponse struct {
	Status     string                     `json:"status"`
	Message    string                     `json:"message"`
	Violations []MCPProxyRuntimeViolation `json:"violations"`
}

// validateMCPProxy is the middleware that runs steps 1-2 above. Step 3
// (runtime-state) lives inside the create/update handlers because it needs
// the parsed APIDefinition, not just the raw OAS object.
func (gw *Gateway) validateMCPProxy(next http.HandlerFunc) http.HandlerFunc {
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

		// OAS-level validation (includes MCPProxy.Validate via oas.go:558).
		if err = mcpObj.Validate(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			// Surface structural MCPProxy violations as 422 with codes.
			var mcpErr *oas.MCPProxyValidationError
			if errors.As(err, &mcpErr) {
				doJSONWrite(w, http.StatusUnprocessableEntity, mcpProxyValidationResponse{
					Status:  "error",
					Message: mcpErr.Error(),
					Codes:   mcpErr.Codes,
					Details: mcpErr.Details,
				})
				return
			}
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		// MCP Proxy spec must actually be present on the extension for POST/PUT.
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			ext := mcpObj.GetTykExtension()
			if ext == nil || ext.Server.MCPProxy == nil {
				doJSONWrite(w, http.StatusBadRequest, apiError("payload missing x-tyk-api-gateway.server.mcpProxy"))
				return
			}
		}

		r.Body = io.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

// handleAddMCPProxy handles POST /mcp-proxies.
func (gw *Gateway) handleAddMCPProxy(r *http.Request, fs afero.Fs) (interface{}, int) {
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
		log.Error("Couldn't decode MCP Proxy OAS object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	oasObj.ExtractTo(&newDef)

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if errResp, errCode := ensureAndValidateAPIID(&newDef); errResp != nil {
		return errResp, errCode
	}

	// Runtime-state validation. Structural validation already ran in middleware.
	ext := oasObj.GetTykExtension()
	if rerr := gw.validateMCPProxyRuntimeState(ext.Server.MCPProxy); rerr.HasViolations() {
		return mcpProxyRuntimeResponse{
			Status:     "error",
			Message:    rerr.Error(),
			Violations: rerr.Violations,
		}, http.StatusConflict
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

	// RFC §12.2 atomicity caveat: write the back-ref BEFORE persisting the
	// Proxy create response, so partial back-ref state is visible to the
	// operator instead of silent. Idempotent on re-save.
	if resp, code := gw.applyMCPProxyBackRefs(newDef.APIID, ext.Server.MCPProxy.Sources, nil, fs); resp != nil {
		return resp, code
	}

	err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	if resp, code := handleBaseVersionUpdate(gw, versionParams, newDef.APIID, fs); resp != nil {
		return resp, code
	}

	return buildSuccessResponse(newDef.APIID, "added")
}

// handleUpdateMCPProxy handles PUT /mcp-proxies/{apiID}.
func (gw *Gateway) handleUpdateMCPProxy(apiID string, r *http.Request, fs afero.Fs) (interface{}, int) {
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

	if !isMCPProxySpec(spec) {
		return apiError("API is not an MCP Proxy"), http.StatusNotFound
	}

	if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
		log.Error("Couldn't decode MCP Proxy OAS object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	oasObj.ExtractTo(&newDef)

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if resp, code := validateAPIIDMatch(apiID, newDef.APIID); resp != nil {
		return resp, code
	}

	ext := oasObj.GetTykExtension()
	if rerr := gw.validateMCPProxyRuntimeState(ext.Server.MCPProxy); rerr.HasViolations() {
		return mcpProxyRuntimeResponse{
			Status:     "error",
			Message:    rerr.Error(),
			Violations: rerr.Violations,
		}, http.StatusConflict
	}

	if err := gw.handleOASServersForUpdate(spec, &newDef, &oasObj); err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	newDef.IsOAS = true

	// Diff old vs new sources to maintain back-refs idempotently.
	var oldSources []oas.MCPSource
	if prev := spec.OAS.GetTykExtension(); prev != nil && prev.Server.MCPProxy != nil {
		oldSources = prev.Server.MCPProxy.Sources
	}
	if resp, code := gw.applyMCPProxyBackRefs(newDef.APIID, ext.Server.MCPProxy.Sources, oldSources, fs); resp != nil {
		return resp, code
	}

	err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
	if err != nil {
		return apiError(err.Error()), errCode
	}

	return buildSuccessResponse(newDef.APIID, "modified")
}

func (gw *Gateway) handleGetMCPProxyListOAS() (interface{}, int) {
	return gw.handleGetOASList(isMCPProxySpec, false)
}

func (gw *Gateway) mcpProxyListHandler(w http.ResponseWriter, _ *http.Request) {
	log.Debug("Requesting MCP Proxy list")
	obj, code := gw.handleGetMCPProxyListOAS()
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleGetMCPProxy(apiID string) (interface{}, int) {
	return gw.handleGetOASByID(apiID, typeCheckFunc("MCP Proxy", isMCPProxySpec))
}

func (gw *Gateway) mcpProxyGetHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Requesting MCP Proxy definition for %q", apiID)

	obj, code := gw.handleGetMCPProxy(apiID)

	if code == http.StatusOK {
		if oasAPI, ok := obj.(*oas.OAS); ok {
			gw.setBaseAPIIDHeader(w, oasAPI)
		}
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) mcpProxyCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Creating MCP Proxy")
	obj, code := gw.handleAddMCPProxy(r, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) mcpProxyUpdateHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Updating MCP Proxy: %q", apiID)
	obj, code := gw.handleUpdateMCPProxy(apiID, r, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

// handleDeleteMCPProxy handles DELETE /mcp-proxies/{apiID}. RFC §12.4: delete
// the MCP Proxy APIDef AND remove its APIID from every source's MCPProxies
// back-ref. Source APIDefs are otherwise untouched.
func (gw *Gateway) handleDeleteMCPProxy(apiID string, fs afero.Fs) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf("Invalid API ID %q: %v", apiID, err)
		return apiError("Invalid API ID"), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
	}

	if !isMCPProxySpec(spec) {
		return apiError("API is not an MCP Proxy"), http.StatusNotFound
	}

	// Pull source APIIDs from the existing spec so we can drop back-refs.
	var sources []oas.MCPSource
	if ext := spec.OAS.GetTykExtension(); ext != nil && ext.Server.MCPProxy != nil {
		sources = ext.Server.MCPProxy.Sources
	}
	// Pass new=nil and old=sources so applyMCPProxyBackRefs treats every source
	// as removed.
	if resp, code := gw.applyMCPProxyBackRefs(apiID, nil, sources, fs); resp != nil {
		return resp, code
	}

	// Reuse the -mcp suffix used by mcp_api.go's delete path; both flows
	// persist OAS files with that suffix when IsMCP() / mcp-proxy.
	suffix := "-oas"
	if spec.IsMCP() {
		suffix = "-mcp"
	}
	if err := deleteAPIFiles(apiID, suffix, gw.GetConfig().AppPath, fs); err != nil {
		log.Warning("Delete failed: ", err)
		return apiError(errMsgDeleteFailed), http.StatusInternalServerError
	}

	handleBaseVersionCleanup(gw, spec, apiID, fs)

	return buildSuccessResponse(apiID, "deleted")
}

func (gw *Gateway) mcpProxyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	log.Debugf("Deleting MCP Proxy: %q", apiID)
	obj, code := gw.handleDeleteMCPProxy(apiID, afero.NewOsFs())
	doJSONWrite(w, code, obj)
}

// applyMCPProxyBackRefs reconciles the Server.MCPProxies back-ref on each
// source APIDef referenced by an MCP Proxy. This is the load-bearing step
// from RFC §12.2 (create) / §12.3 (update diff) / §12.4 (delete = full
// removal).
//
// Behaviour:
//   - Sources present in newSources but not oldSources: append proxyAPIID
//     (idempotent — append only when not already present).
//   - Sources present in oldSources but not newSources: remove proxyAPIID.
//   - Sources present in both: no-op.
//
// Atomicity caveat (RFC §12.2): on partial failure mid-iteration, returns a
// 500 mcpProxyRuntimeResponse with code partial_back_ref_state listing which
// source APIIDs succeeded vs failed. Operator recovery: re-save the Proxy.
//
// Only loopback sources (with non-empty SourceAPIID) need back-refs; upstream
// sources are skipped.
func (gw *Gateway) applyMCPProxyBackRefs(proxyAPIID string, newSources, oldSources []oas.MCPSource, fs afero.Fs) (interface{}, int) {
	newIDs := loopbackSourceIDSet(newSources)
	oldIDs := loopbackSourceIDSet(oldSources)

	toAdd := make([]string, 0)
	toRemove := make([]string, 0)
	for id := range newIDs {
		if _, present := oldIDs[id]; !present {
			toAdd = append(toAdd, id)
		}
	}
	for id := range oldIDs {
		if _, present := newIDs[id]; !present {
			toRemove = append(toRemove, id)
		}
	}

	type result struct {
		sourceID string
		err      error
	}
	var (
		succeeded []string
		failures  []result
	)

	apply := func(sourceID string, mutate func(ext *oas.XTykAPIGateway)) {
		spec := gw.getApiSpec(sourceID)
		if spec == nil {
			// Source vanished between admission gate and now; record failure.
			failures = append(failures, result{sourceID: sourceID, err: errSourceVanished})
			return
		}
		// Operate on a deep copy so we don't race with hot-reload readers.
		oasCopy, copyErr := copyOASForPersistence(&spec.OAS)
		if copyErr != nil {
			failures = append(failures, result{sourceID: sourceID, err: copyErr})
			return
		}
		ext := oasCopy.GetTykExtension()
		if ext == nil {
			failures = append(failures, result{sourceID: sourceID, err: errSourceMissingTykExt})
			return
		}
		mutate(ext)

		apiDefCopy, copyErr := copyAPIDefForPersistence(spec.APIDefinition)
		if copyErr != nil {
			failures = append(failures, result{sourceID: sourceID, err: copyErr})
			return
		}
		oasCopy.ExtractTo(apiDefCopy)
		if err, _ := gw.writeOASAndAPIDefToFile(fs, apiDefCopy, oasCopy); err != nil {
			failures = append(failures, result{sourceID: sourceID, err: err})
			return
		}
		// Reflect on the live spec so subsequent reads in this process see the
		// updated back-ref before the next reload. Hot-reload will re-load
		// from disk authoritatively.
		spec.OAS = *oasCopy
		spec.APIDefinition = apiDefCopy
		succeeded = append(succeeded, sourceID)
	}

	for _, id := range toAdd {
		apply(id, func(ext *oas.XTykAPIGateway) {
			for _, existing := range ext.Server.MCPProxies {
				if existing == proxyAPIID {
					return
				}
			}
			ext.Server.MCPProxies = append(ext.Server.MCPProxies, proxyAPIID)
		})
	}

	for _, id := range toRemove {
		apply(id, func(ext *oas.XTykAPIGateway) {
			filtered := ext.Server.MCPProxies[:0]
			for _, existing := range ext.Server.MCPProxies {
				if existing == proxyAPIID {
					continue
				}
				filtered = append(filtered, existing)
			}
			ext.Server.MCPProxies = filtered
		})
	}

	if len(failures) == 0 {
		return nil, 0
	}

	violations := make([]MCPProxyRuntimeViolation, 0, len(failures))
	for _, f := range failures {
		violations = append(violations, MCPProxyRuntimeViolation{
			Code:        MCPProxyErrPartialBackRefState,
			SourceAPIID: f.sourceID,
			Message:     f.err.Error(),
		})
	}
	// Note succeeded sources in the message so the operator can see the
	// partial state when retrying.
	msg := "partial back-ref state; re-save the proxy to retry (idempotent)"
	if len(succeeded) > 0 {
		msg += "; back-refs already written for: "
		for i, id := range succeeded {
			if i > 0 {
				msg += ","
			}
			msg += id
		}
	}
	return mcpProxyRuntimeResponse{
		Status:     "error",
		Message:    msg,
		Violations: violations,
	}, http.StatusInternalServerError
}

func loopbackSourceIDSet(sources []oas.MCPSource) map[string]struct{} {
	out := make(map[string]struct{}, len(sources))
	for i := range sources {
		s := &sources[i]
		if s.BackendMode != "loopback" {
			continue
		}
		if s.SourceAPIID == "" {
			continue
		}
		out[s.SourceAPIID] = struct{}{}
	}
	return out
}

var (
	errSourceVanished      = errors.New("source APIDef no longer loaded")
	errSourceMissingTykExt = errors.New("source APIDef has no x-tyk-api-gateway extension")
)
