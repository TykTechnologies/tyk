package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	BaseMiddleware
}

func (t *TransformHeaders) Name() string {
	return "TransformHeaders"
}

func (t *TransformHeaders) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformHeader) > 0 ||
			len(version.GlobalHeaders) > 0 ||
			len(version.GlobalHeadersRemove) > 0 {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, versionPaths, _, _ := t.Spec.Version(r)

	// Manage global headers first - remove
	for _, gdKey := range vInfo.GlobalHeadersRemove {
		t.Logger().Debug("Removing: ", gdKey)
		r.Header.Del(gdKey)
	}

	// Add
	ignoreCanonical := config.Global().IgnoreCanonicalMIMEHeaderKey
	for nKey, nVal := range vInfo.GlobalHeaders {
		t.Logger().Debug("Adding: ", nKey)
		setCustomHeader(r.Header, nKey, replaceTykVariables(r, nVal, false), ignoreCanonical)
	}

	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, HeaderInjected)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			r.Header.Del(dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			setCustomHeader(r.Header, nKey, replaceTykVariables(r, nVal, false), ignoreCanonical)
		}
	}

	return nil, http.StatusOK
}
