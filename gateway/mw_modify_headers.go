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

	versionPaths := t.Spec.RxPaths[vInfo.Name]
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, HeaderInjected)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			r.Header.Del(dKey)
			logger.Debugf("Removing: %s", dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			setCustomHeader(r.Header, nKey, t.Gw.ReplaceTykVariables(r, nVal, false), ignoreCanonical)
			logger.Debugf("Adding: %s: %s", nKey, nVal)
		}
	}

	return nil, http.StatusOK
}
