package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// Oauth2KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type Oauth2KeyExists struct {
	BaseMiddleware
}

func (k *Oauth2KeyExists) Name() string {
	return "Oauth2KeyExists"
}

func (k *Oauth2KeyExists) EnabledForSpec() bool {
	return k.Spec.UseOauth2
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *Oauth2KeyExists) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	// We're using OAuth, start checking for access keys
	token := r.Header.Get("Authorization")
	parts := strings.Split(token, " ")
	logEntry := getLogEntryForRequest(r, "", nil)
	if len(parts) < 2 {
		logEntry.Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), 400
	}

	if strings.ToLower(parts[0]) != "bearer" {
		logEntry.Info("Bearer token malformed")

		return errors.New("Bearer token malformed"), 400
	}

	accessToken := parts[1]
	session, keyExists := k.CheckSessionAndIdentityForValidKey(accessToken)

	if !keyExists {
		logEntry = getLogEntryForRequest(r, accessToken, nil)
		logEntry.Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k, r, accessToken)
		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return errors.New("Key not authorised"), 403
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.OAuthKey, apidef.UnsetAuth:
		ctxSetSession(r, &session)
		ctxSetAuthToken(r, accessToken)
	}

	// Request is valid, carry on
	return nil, 200
}
