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
	// TODO: Read from API definition
	allowedAuths := [][]string{{"Basic", "AuthToken"}, {"Basic2", "AuthToken2"}}

	authInfo := r.Context().Value("authSuccess")
	if authInfo == nil {
		// No auth middleware was executed yet
		return nil, http.StatusUnauthorized
	}

	currAuthMw, ok := authInfo.([]string)
	if !ok {
		// Invalid auth info type
		return nil, http.StatusUnauthorized
	}

	// Check if current auth middleware combination matches any allowed combination
	for _, allowedCombination := range allowedAuths {
		if len(currAuthMw) != len(allowedCombination) {
			continue
		}

		matches := true
		for i, auth := range allowedCombination {
			if currAuthMw[i] != auth {
				matches = false
				break
			}
		}

		if matches {
			return nil, http.StatusOK
		}
	}

	// No valid auth combination found
	return nil, http.StatusUnauthorized
}
