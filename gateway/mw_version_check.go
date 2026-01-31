package gateway

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/routers"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
)

const XTykAPIExpires = "x-tyk-api-expires"

// VersionCheck will check whether the version of the requested API the request is accessing has any restrictions on URL endpoints
type VersionCheck struct {
	*BaseMiddleware

	sh SuccessHandler
}

func (v *VersionCheck) Init() {
	v.sh = SuccessHandler{v.BaseMiddleware}
}

func (v *VersionCheck) Name() string {
	return "VersionCheck"
}

func (v *VersionCheck) DoMockReply(w http.ResponseWriter, meta apidef.MockResponseMeta) {
	responseMessage := []byte(meta.Body)
	for header, value := range meta.Headers {
		w.Header().Add(header, value)
	}

	w.WriteHeader(meta.Code)
	w.Write(responseMessage)
}

type Operation struct {
	*oas.Operation
	route      *routers.Route
	pathParams map[string]string
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	targetVersion := v.Spec.getVersionFromRequest(r)
	if targetVersion == "" {
		targetVersion = v.Spec.VersionDefinition.Default
	}

	ctxSetSpanAttributes(r, v.Name(), otel.APIVersionAttribute(targetVersion))

	isBase := func(vName string) bool {
		return vName == apidef.Self || vName == v.Spec.VersionDefinition.Name
	}

	if v.Spec.VersionDefinition.Enabled && !isBase(targetVersion) {
		if targetVersion == "" {
			return errors.New(string(VersionNotFound)), http.StatusForbidden
		}

		subVersionID := v.Spec.VersionDefinition.Versions[targetVersion]
		handler, _, found := v.Gw.findInternalHttpHandlerByNameOrID(subVersionID)
		if !found {
			if !v.Spec.VersionDefinition.FallbackToDefault {
				return errors.New(string(VersionDoesNotExist)), http.StatusNotFound
			}

			if isBase(v.Spec.VersionDefinition.Default) {
				goto outside
			}

			targetID, ok := v.Spec.VersionDefinition.Versions[v.Spec.VersionDefinition.Default]
			if !ok {
				log.Errorf("fallback to default but %s is not in the versions list", v.Spec.VersionDefinition.Default)
				return errors.New(http.StatusText(http.StatusInternalServerError)), http.StatusInternalServerError
			}

			handler, _, found = v.Gw.findInternalHttpHandlerByNameOrID(targetID)
			if !found {
				log.Errorf("fallback to default but there is no such API found with the id: %s", targetID)
				return errors.New(http.StatusText(http.StatusInternalServerError)), http.StatusInternalServerError
			}
		}

		v.Spec.SanitizeProxyPaths(r)

		handler.ServeHTTP(w, r)
		return nil, middleware.StatusRespond
	}
outside:
	// Check versioning, blacklist, whitelist and ignored status
	requestValid, stat := v.Spec.RequestValid(r)
	if !requestValid {
		if stat == MCPPrimitiveNotFound {
			state := httpctx.GetJSONRPCRoutingState(r)
			if state != nil {
				allowListEnabled := v.getPrimitiveAllowListFlag(r.URL.Path)

				if allowListEnabled {
					return errors.New("Access to this resource has been disallowed"), http.StatusForbidden
				}

				state.NextVEM = ""
				httpctx.SetJSONRPCRoutingState(r, state)
				r.URL.Path = state.OriginalPath
				r.URL.RawQuery = ""
				return nil, http.StatusOK
			}
			return errors.New(http.StatusText(http.StatusNotFound)), http.StatusNotFound
		}

		// Fire a versioning failure event
		v.FireEvent(EventVersionFailure, EventVersionFailureMeta{
			EventMetaDefault: EventMetaDefault{
				Message:            "Attempted access to disallowed version / path.",
				OriginatingRequest: EncodeRequestToEvent(r),
			},
			Path:   r.URL.Path,
			Origin: request.RealIP(r),
			Reason: string(stat),
		})
		return errors.New("Attempted access to disallowed version / path."), http.StatusForbidden
	}

	versionInfo, _ := v.Spec.Version(r)
	versionPaths := v.Spec.RxPaths[versionInfo.Name]

	// For MCP primitives with allowlist enabled: check if VEM has WhiteList entry
	// If allowlist is on but VEM doesn't have a WhiteList entry → block
	if httpctx.IsJsonRPCRouting(r) && mcp.IsPrimitiveVEMPath(r.URL.Path) {
		allowListEnabled := v.getPrimitiveAllowListFlag(r.URL.Path)
		if allowListEnabled {
			if err := v.checkVEMWhiteListEntry(r.URL.Path, versionPaths, "Access to this resource has been disallowed"); err != nil {
				return err, http.StatusForbidden
			}
		}
	}

	// For JSON-RPC operations with allowlist enabled: check if operation VEM has WhiteList entry
	// If OperationsAllowListEnabled but operation doesn't have a WhiteList entry → block
	if httpctx.IsJsonRPCRouting(r) && strings.HasPrefix(r.URL.Path, jsonrpc.MethodVEMPrefix) {
		if v.Spec.OperationsAllowListEnabled {
			if err := v.checkVEMWhiteListEntry(r.URL.Path, versionPaths, "Access to this operation has been disallowed"); err != nil {
				return err, http.StatusForbidden
			}
		}
	}

	whiteListStatus := v.Spec.WhiteListEnabled[versionInfo.Name]

	// We handle redirects before ignores in case we aren't using a whitelist
	if stat == StatusRedirectFlowByReply {
		_, meta := v.Spec.URLAllowedAndIgnored(r, versionPaths, whiteListStatus)
		var mockMeta apidef.MockResponseMeta
		var ok bool
		if mockMeta, ok = meta.(apidef.MockResponseMeta); !ok {
			endpointMethodMeta := meta.(*apidef.EndpointMethodMeta)
			mockMeta.Body = endpointMethodMeta.Data
			mockMeta.Headers = endpointMethodMeta.Headers
			mockMeta.Code = endpointMethodMeta.Code
		}

		v.DoMockReply(w, mockMeta)
		return nil, middleware.StatusRespond
	}

	if !v.Spec.ExpirationTs.IsZero() {
		w.Header().Set(XTykAPIExpires, v.Spec.ExpirationTs.Format(time.RFC1123))
	} else if expTime := versionInfo.ExpiryTime(); !expTime.IsZero() { // Deprecated
		w.Header().Set(XTykAPIExpires, expTime.Format(time.RFC1123))
	}

	if stat == StatusOkAndIgnore {
		ctxSetRequestStatus(r, stat)
	}

	return nil, http.StatusOK
}

// getPrimitiveAllowListFlag returns the allowlist flag for a given MCP primitive VEM path.
func (v *VersionCheck) getPrimitiveAllowListFlag(path string) bool {
	if strings.HasPrefix(path, mcp.ToolPrefix) {
		return v.Spec.ToolsAllowListEnabled
	} else if strings.HasPrefix(path, mcp.ResourcePrefix) {
		return v.Spec.ResourcesAllowListEnabled
	} else if strings.HasPrefix(path, mcp.PromptPrefix) {
		return v.Spec.PromptsAllowListEnabled
	}
	return false
}

// checkVEMWhiteListEntry checks if a VEM path has a WhiteList entry.
// Returns an error if allowlist is active but no WhiteList entry is found.
func (v *VersionCheck) checkVEMWhiteListEntry(path string, versionPaths []URLSpec, errorMessage string) error {
	for i := range versionPaths {
		if versionPaths[i].Status == WhiteList && versionPaths[i].matchesPath(path, v.Spec) {
			return nil // WhiteList entry found
		}
	}
	return errors.New(errorMessage) // No WhiteList entry found
}
