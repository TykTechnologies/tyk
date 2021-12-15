package gateway

import (
	"errors"
	"net/http"
)

// AccessRightsCheck is a middleware that will check if the key bing used to access the API has
// permission to access the specific version. If no permission data is in the user.SessionState, then
// it is assumed that the user can go through.
type AccessRightsCheck struct {
	BaseMiddleware
}

func (a *AccessRightsCheck) Name() string {
	return "AccessRightsCheck"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (a *AccessRightsCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	baseAPI := ctxGetVersionBaseAPI(r)
	if baseAPI == nil {
		baseAPI = a.Spec
	}

	session := ctxGetSession(r)

	// If there's nothing in our profile, we let them through to the next phase
	if len(session.AccessRights) > 0 {
		// Otherwise, run auth checks
		versionList, apiExists := session.AccessRights[baseAPI.APIID]
		if !apiExists {
			a.Logger().Info("Attempted access to unauthorised API")
			return errors.New("Access to this API has been disallowed"), http.StatusForbidden
		}

		// Find the version in their key access details
		found := false
		if baseAPI.VersionData.NotVersioned && !baseAPI.VersionDefinition.Enabled {
			// Not versioned, no point checking version access rights
			found = true
		} else {
			targetVersion := baseAPI.getVersionFromRequest(r)
			if targetVersion == "" {
				if baseAPI.VersionDefinition.Enabled {
					targetVersion = baseAPI.VersionDefinition.Default
				} else {
					targetVersion = baseAPI.VersionData.DefaultVersion
				}
			}

			for _, vInfo := range versionList.Versions {
				if vInfo == targetVersion {
					found = true
					break
				}
			}
		}

		if !found {
			a.Logger().Info("Attempted access to unauthorised API version.")
			return errors.New("Access to this API has been disallowed"), http.StatusForbidden
		}
	}

	return nil, 200
}
