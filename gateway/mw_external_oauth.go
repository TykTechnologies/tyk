package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type ExternalOAuthMiddleware struct {
	BaseMiddleware
}

func (k *ExternalOAuthMiddleware) Name() string {
	return "ExternalOAuth"
}

func (k *ExternalOAuthMiddleware) EnabledForSpec() bool {
	return k.Spec.ExternalOAuth.Enabled
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *ExternalOAuthMiddleware) getAuthType() string {
	return apidef.ExternalOAuthType
}

func (k *ExternalOAuthMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	token, _ := k.getAuthToken(k.getAuthType(), r)
	if token == "" {
		return errors.New("authorization field missing"), http.StatusBadRequest
	}

	token = stripBearer(token)

	var (
		valid      bool
		err        error
		identifier string
	)

	if len(k.Spec.ExternalOAuth.Providers) == 0 {
		return errors.New("there should be at least one provider configured"), http.StatusNotFound
	}

	// Just the first one will be used, later there can be multiple providers supported
	provider := k.Spec.ExternalOAuth.Providers[0]

	if provider.JWT.Enabled {
		valid, identifier, err = k.jwt(token)
	} else if provider.Introspection.Enabled {
		valid, identifier, err = k.introspection(token)
	} else {
		return errors.New("access token validation method is not specified"), http.StatusInternalServerError
	}

	if err != nil {
		return errors.New("error happened during the access token validation"), http.StatusInternalServerError
	}

	if !valid {
		return errors.New("access token is not valid"), http.StatusUnauthorized
	}

	var virtualSession user.SessionState
	virtualSession, exists := k.CheckSessionAndIdentityForValidKey(identifier, r)
	if !exists {
		virtualSession = k.generateVirtualSessionFor(r, identifier)
	}

	ctxSetSession(r, &virtualSession, false, k.Gw.GetConfig().HashKeys)

	// Request is valid, carry on
	return nil, http.StatusOK
}

// jwt makes access token validation without making a network call and validates access token locally.
// The access token should be JWT type.
func (k *ExternalOAuthMiddleware) jwt(accessToken string) (bool, string, error) {
	return false, "", errors.New("jwt validation not implemented yet")
}

// introspection makes an introspection request to third-party provider to check whether the access token is valid or not.
// The access token can be both JWT and opaque type.
func (k *ExternalOAuthMiddleware) introspection(accessToken string) (bool, string, error) {
	return false, "", errors.New("introspection not implemented yet")
}

// generateVirtualSessionFor generates a virtual session for the given access token by using its identifier.
func (k *ExternalOAuthMiddleware) generateVirtualSessionFor(r *http.Request, identifier string) user.SessionState {
	return user.SessionState{}
}
