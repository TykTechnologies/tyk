package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/v3/apidef"
)

// TrackEndpointMiddleware sets context variables to enable or disable whether Tyk should record analytitcs for a specific path.
type TrackEndpointMiddleware struct {
	BaseMiddleware
}

func (t *TrackEndpointMiddleware) Name() string {
	return "TrackEndpointMiddleware"
}

func (t *TrackEndpointMiddleware) EnabledForSpec() bool {
	if !t.Spec.GlobalConfig.EnableAnalytics || t.Spec.DoNotTrack {
		return false
	}

	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TrackEndpoints) > 0 {
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TrackEndpointMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := t.Spec.Version(r)
	foundTracked, metaTrack := t.Spec.CheckSpecMatchesStatus(r, versionPaths, RequestTracked)
	if foundTracked {
		ctxSetTrackedPath(r, metaTrack.(*apidef.TrackEndpointMeta).Path)
	}

	foundDnTrack, _ := t.Spec.CheckSpecMatchesStatus(r, versionPaths, RequestNotTracked)
	if foundDnTrack {
		ctxSetDoNotTrack(r, true)
	}

	return nil, http.StatusOK
}
