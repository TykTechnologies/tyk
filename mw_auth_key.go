package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	BaseMiddleware
}

func (k *AuthKey) Name() string {
	return "AuthKey"
}

func (k *AuthKey) setContextVars(r *http.Request, token string) {
	// Flatten claims and add to context
	if !k.Spec.EnableContextVars {
		return
	}
	if cnt := ctxGetData(r); cnt != nil {
		// Key data
		cnt["token"] = token
		ctxSetData(r, cnt)
	}
}

func (k *AuthKey) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	config := k.Spec.Auth

	key := r.Header.Get(config.AuthHeaderName)

	paramName := config.ParamName
	if config.UseParam || paramName != "" {
		if paramName == "" {
			paramName = config.AuthHeaderName
		}

		paramValue := r.URL.Query().Get(paramName)

		// Only use the paramValue if it has an actual value
		if paramValue != "" {
			key = paramValue
		}
	}

	cookieName := config.CookieName
	if config.UseCookie || cookieName != "" {
		if cookieName == "" {
			cookieName = config.AuthHeaderName
		}

		authCookie, err := r.Cookie(cookieName)
		cookieValue := ""
		if err == nil {
			cookieValue = authCookie.Value
		}

		if cookieValue != "" {
			key = cookieValue
		}
	}

	// If key not provided in header or cookie and client certificate is provided, try to find certificate based key
	if config.UseCertificate && key == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		key = k.Spec.OrgID + certs.HexSHA256(r.TLS.PeerCertificates[0].Raw)
	}

	if key == "" {
		// No header value, fail
		logEntry := getLogEntryForRequest(r, "", nil)
		logEntry.Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), http.StatusUnauthorized
	}

	// Ignore Bearer prefix on token if it exists
	key = stripBearer(key)

	// Check if API key valid
	session, keyExists := k.CheckSessionAndIdentityForValidKey(key)
	if !keyExists {
		logEntry := getLogEntryForRequest(r, key, nil)
		logEntry.Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k, r, key)

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "1")

		return errors.New("Key not authorised"), http.StatusForbidden
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.AuthToken, apidef.UnsetAuth:
		ctxSetSession(r, &session)
		ctxSetAuthToken(r, key)
		k.setContextVars(r, key)
	}

	return nil, http.StatusOK
}

func stripBearer(token string) string {
	token = strings.Replace(token, "Bearer", "", 1)
	token = strings.Replace(token, "bearer", "", 1)
	return strings.TrimSpace(token)
}

func AuthFailed(m TykMiddleware, r *http.Request, token string) {
	m.Base().FireEvent(EventAuthFailure, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           requestIP(r),
		Key:              token,
	})
}
