package main

import "net/http"

import (
	"errors"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	"strings"
)

// Oauth2KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type Oauth2KeyExists struct {
	*TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (k *Oauth2KeyExists) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (k *Oauth2KeyExists) GetConfig() (interface{}, error) {
	return nil, nil
}

func (a *Oauth2KeyExists) IsEnabledForSpec() bool {
	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *Oauth2KeyExists) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// We're using OAuth, start checking for access keys
	authHeaderValue := r.Header.Get("Authorization")
	parts := strings.Split(authHeaderValue, " ")
	if len(parts) < 2 {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), 400
	}

	if strings.ToLower(parts[0]) != "bearer" {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("Bearer token malformed")

		return errors.New("Bearer token malformed"), 400
	}

	accessToken := parts[1]
	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(accessToken)

	if !keyExists {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    accessToken,
		}).Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k.TykMiddleware, r, accessToken)
		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "-1")

		return errors.New("Key not authorised"), 403
	}

	// Set session state on context, we will need it later
	if (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.OAuthKey) || (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.UnsetAuth) {
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, accessToken)
	}

	// Request is valid, carry on
	return nil, 200
}
