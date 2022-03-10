package gateway

import (
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	checkOAuthClientDeletedInetrval = 1 * time.Second
)

const (
	ErrOAuthAuthorizationFieldMissing   = "oauth.auth_field_missing"
	ErrOAuthAuthorizationFieldMalformed = "oauth.auth_field_malformed"
	ErrOAuthKeyNotFound                 = "oauth.key_not_found"
	ErrOAuthClientDeleted               = "oauth.client_deleted"
)

func init() {
	TykErrors[ErrOAuthAuthorizationFieldMissing] = config.TykError{
		Message: "Authorization field missing",
		Code:    http.StatusBadRequest,
	}

	TykErrors[ErrOAuthAuthorizationFieldMalformed] = config.TykError{
		Message: "Bearer token malformed",
		Code:    http.StatusBadRequest,
	}

	TykErrors[ErrOAuthKeyNotFound] = config.TykError{
		Message: "Key not authorised",
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrOAuthClientDeleted] = config.TykError{
		Message: "Key not authorised. OAuth client access was revoked",
		Code:    http.StatusForbidden,
	}
}

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

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *Oauth2KeyExists) getAuthType() string {
	return apidef.OAuthType
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *Oauth2KeyExists) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := k.Logger()
	// We're using OAuth, start checking for access keys
	token, _ := k.getAuthToken(k.getAuthType(), r)
	parts := strings.Split(token, " ")

	if len(parts) < 2 {
		logger.Info("Attempted access with malformed header, no auth header found.")

		return errorAndStatusCode(ErrOAuthAuthorizationFieldMissing)
	}

	if strings.ToLower(parts[0]) != "bearer" {
		logger.Info("Bearer token malformed")

		return errorAndStatusCode(ErrOAuthAuthorizationFieldMalformed)
	}

	accessToken := parts[1]
	logger = logger.WithField("key", k.Gw.obfuscateKey(accessToken))

	// get session for the given oauth token
	session, keyExists := k.CheckSessionAndIdentityForValidKey(accessToken, r)
	accessToken = session.KeyID

	if !keyExists {
		logger.Warning("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k, r, accessToken)
		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return errorAndStatusCode(ErrOAuthKeyNotFound)
	}

	// Make sure OAuth-client is still present
	oauthClientDeletedKey := "oauth-del-" + k.Spec.APIID + session.OauthClientID
	oauthClientDeleted := false
	// check if that oauth client was deleted with using  memory cache first
	if val, found := k.Gw.UtilCache.Get(oauthClientDeletedKey); found {
		oauthClientDeleted = val.(bool)
	} else {
		// if not cached in memory then hit Redis to get oauth-client from there
		if _, err := k.Spec.OAuthManager.OsinServer.Storage.GetClient(session.OauthClientID); err != nil {
			// set this oauth client as deleted in memory cache for the next N sec
			k.Gw.UtilCache.Set(oauthClientDeletedKey, true, checkOAuthClientDeletedInetrval)
			oauthClientDeleted = true
		} else {
			// set this oauth client as NOT deleted in memory cache for next N sec
			k.Gw.UtilCache.Set(oauthClientDeletedKey, false, checkOAuthClientDeletedInetrval)
		}
	}
	if oauthClientDeleted {
		logger.WithField("oauthClientID", session.OauthClientID).Warning("Attempted access for deleted OAuth client.")
		return errorAndStatusCode(ErrOAuthClientDeleted)
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.OAuthKey, apidef.UnsetAuth:
		ctxSetSession(r, &session, false, k.Gw.GetConfig().HashKeys)
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}
