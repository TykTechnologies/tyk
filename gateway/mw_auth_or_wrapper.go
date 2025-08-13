package gateway

import (
	"net/http"
)

// AuthORWrapper is a middleware that handles OR logic for multiple authentication methods.
// When multiple security requirements are defined (len(SecurityRequirements) > 1),
// it tries each auth method until one succeeds.
type AuthORWrapper struct {
	BaseMiddleware
	authMiddlewares []TykMiddleware
}

// ProcessRequest handles the OR logic for authentication
func (a *AuthORWrapper) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Auto-detect OR logic from security requirements
	if len(a.Spec.SecurityRequirements) <= 1 {
		// Single requirement or empty = AND logic (default behavior)
		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	// Multiple requirements = OR Logic: Try each requirement until one succeeds
	var lastError error
	var lastCode int

	for _, mw := range a.authMiddlewares {
		// Clone the request to avoid side effects between attempts
		rClone := r.Clone(r.Context())

		err, code := mw.ProcessRequest(w, rClone, nil)
		if err == nil {
			// Success! Copy any modifications back to original request
			*r = *rClone
			return nil, http.StatusOK
		}

		// Keep track of last error and code
		lastError = err
		lastCode = code
	}

	// All methods failed - return the last error and status code
	// This maintains backward compatibility with error messages
	return lastError, lastCode
}

// Name returns the name of the middleware
func (a *AuthORWrapper) Name() string {
	return "AuthORWrapper"
}

// EnabledForSpec checks if the middleware is enabled for the API spec
func (a *AuthORWrapper) EnabledForSpec() bool {
	// This middleware is automatically enabled when multiple security requirements exist
	return len(a.Spec.SecurityRequirements) > 1 && len(a.authMiddlewares) > 1
}

// Init initializes the AuthORWrapper middleware
func (a *AuthORWrapper) Init() {
	a.authMiddlewares = []TykMiddleware{}
}

// SetAuthMiddlewares sets the authentication middlewares to be used with OR logic
func (a *AuthORWrapper) SetAuthMiddlewares(middlewares []TykMiddleware) {
	a.authMiddlewares = middlewares
}