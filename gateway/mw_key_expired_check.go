package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/v3/request"
)

// KeyExpired middleware will check if the requesting key is expired or not. It makes use of the authManager to do so.
type KeyExpired struct {
	BaseMiddleware
}

func (k *KeyExpired) Name() string {
	return "KeyExpired"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *KeyExpired) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := k.Logger()
	session := ctxGetSession(r)
	if session == nil {
		return errors.New("Session state is missing or unset! Please make sure that auth headers are properly applied"), http.StatusBadRequest
	}

	token := ctxGetAuthToken(r)
	if session.IsInactive {
		logger.Info("Attempted access from inactive key.")
		// Fire a key expired event
		k.FireEvent(EventKeyExpired, EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "Attempted access from inactive key.", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           request.RealIP(r),
			Key:              token,
		})

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return errors.New("Key is inactive, please renew"), http.StatusForbidden
	}

	if !k.Spec.AuthManager.KeyExpired(session) {
		return nil, http.StatusOK
	}
	logger.Info("Attempted access from expired key.")

	k.FireEvent(EventKeyExpired, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Attempted access from expired key.", OriginatingRequest: EncodeRequestToEvent(r)},
		Path:             r.URL.Path,
		Origin:           request.RealIP(r),
		Key:              token,
	})
	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "-1")

	return errors.New("Key has expired, please renew"), http.StatusUnauthorized
}
