package gateway

import (
	"net/http"
)

type MultiAuth struct {
	*BaseMiddleware
}

func (k *MultiAuth) Name() string {
	return "MultiAuth"
}

func (k *MultiAuth) EnabledForSpec() bool {
	// TODO: actually read from config
	return true
}

func (k *MultiAuth) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	session := ctxGetSession(r)

	// TODO: Extend the error message
	if session == nil {
		// None of middlewares were able to auth the user
		return nil, http.StatusUnauthorized
	}

	return nil, http.StatusOK
}
