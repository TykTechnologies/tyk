package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	*BaseMiddleware
}

func (t *TransformHeaders) Name() string {
	return "RequestHeaderInjector"
}

func (t *TransformHeaders) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if version.GlobalHeadersEnabled() {
			return true
		}

		if version.HasEndpointReqHeader() {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := t.Spec.Version(r)

	ignoreCanonical := t.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	logger := t.Logger()

	// Manage global headers first - remove
	if !vInfo.GlobalHeadersDisabled {
		for _, gdKey := range vInfo.GlobalHeadersRemove {
			logger.Debugf("Removing global: %s", gdKey)
			r.Header.Del(gdKey)
		}

		// Add
		for nKey, nVal := range vInfo.GlobalHeaders {
			logger.Debugf("Adding global: %s: %s", nKey, nVal)
			setCustomHeader(r.Header, nKey, t.Gw.ReplaceTykVariables(r, nVal, false), ignoreCanonical)
		}
	}

	// Use generic VEM chain helper to get all matching header injection specs
	// This works for both MCP APIs (checks all VEMs in chain) and non-MCP APIs (checks current path)
	versionPaths := t.Spec.RxPaths[vInfo.Name]
	specs := t.Spec.FindAllVEMChainSpecs(r, versionPaths, HeaderInjected)

	logger.Infof("[DEBUG] HeaderTransform: Found %d matching specs for path %s", len(specs), r.URL.Path)

	// Apply headers from all matching specs sequentially
	// For MCP: applies operation-level headers, then tool-level headers
	// For non-MCP: applies only the matched path's headers
	for i, spec := range specs {
		logger.Infof("[DEBUG] HeaderTransform: Applying spec %d/%d - Path: %s, Method: %s, Headers: %+v",
			i+1, len(specs), spec.InjectHeaders.Path, spec.InjectHeaders.Method, spec.InjectHeaders.AddHeaders)
		t.applyHeaderMeta(r, &spec.InjectHeaders, ignoreCanonical)
	}

	return nil, http.StatusOK
}

// applyHeaderMeta applies header deletions and additions from a HeaderInjectionMeta.
func (t *TransformHeaders) applyHeaderMeta(r *http.Request, hmeta *apidef.HeaderInjectionMeta, ignoreCanonical bool) {
	logger := t.Logger()

	for _, dKey := range hmeta.DeleteHeaders {
		r.Header.Del(dKey)
		logger.Debugf("Removing: %s", dKey)
	}
	for nKey, nVal := range hmeta.AddHeaders {
		setCustomHeader(r.Header, nKey, t.Gw.ReplaceTykVariables(r, nVal, false), ignoreCanonical)
		logger.Debugf("Adding: %s: %s", nKey, nVal)
	}
}
