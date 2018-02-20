package main

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
	accessingVersion := a.Spec.getVersionFromRequest(r)
	if accessingVersion == "" {
		if a.Spec.VersionData.DefaultVersion != "" {
			accessingVersion = a.Spec.VersionData.DefaultVersion
		}
	}
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	// If there's nothing in our profile, we let them through to the next phase
	if len(session.AccessRights) > 0 {
		// Otherwise, run auth checks
		versionList, apiExists := session.AccessRights[a.Spec.APIID]
		if !apiExists {
			logEntry := getLogEntryForRequest(
				r,
				token,
				map[string]interface{}{
					"api_found": false,
				},
			)
			logEntry.Info("Attempted access to unauthorised API.")

			return errors.New("Access to this API has been disallowed"), 403
		}

		// Find the version in their key access details
		found := false
		if a.Spec.VersionData.NotVersioned {
			// Not versioned, no point checking version access rights
			found = true
		} else {
			for _, vInfo := range versionList.Versions {
				if vInfo == accessingVersion {
					found = true
					break
				}
			}
		}

		if !found {
			// Not found? Bounce
			logEntry := getLogEntryForRequest(
				r,
				token,
				map[string]interface{}{
					"api_found":     true,
					"version_found": false,
				},
			)
			logEntry.Info("Attempted access to unauthorised API version.")

			return errors.New("Access to this API has been disallowed"), 403
		}
	}

	return nil, 200
}
