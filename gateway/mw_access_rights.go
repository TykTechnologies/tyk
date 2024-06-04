package gateway

import (
	"errors"
	"net/http"
)

// AccessRightsCheck is a middleware that will check if the key bing used to access the API has
// permission to access the specific version. If no permission data is in the user.SessionState, then
// it is assumed that the user can go through.
type AccessRightsCheck struct {
	*BaseMiddleware
}

func (a *AccessRightsCheck) Name() string {
	return "AccessRightsCheck"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (a *AccessRightsCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)

	// If there's nothing in our profile, we let them through to the next phase
	if len(session.AccessRights) == 0 {
		return nil, http.StatusOK
	}

	// Otherwise, run auth checks
	versionList, apiExists := session.AccessRights[a.Spec.APIID]
	if !apiExists {
		a.Logger().Info("Attempted access to unauthorised API")
		return errors.New("Access to this API has been disallowed"), http.StatusForbidden
	}

	if a.Spec.VersionData.NotVersioned {
		return nil, http.StatusOK
	}

	targetVersion := a.Spec.getVersionFromRequest(r)
	if targetVersion == "" {
		targetVersion = a.Spec.VersionData.DefaultVersion
	}

	for _, vName := range versionList.Versions {
		if vName == targetVersion {
			return nil, http.StatusOK
		}
	}

	if a.Spec.VersionDefinition.FallbackToDefault && targetVersion != a.Spec.VersionData.DefaultVersion {
		for _, vName := range versionList.Versions {
			if vName == a.Spec.VersionData.DefaultVersion {
				return nil, http.StatusOK
			}
		}
	}

	a.Logger().Info("Attempted access to unauthorised API version.")
	return errors.New("Access to this API has been disallowed"), http.StatusForbidden
}
