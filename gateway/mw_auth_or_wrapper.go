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

	// Determine processing mode (OAS-only feature)
	processingMode := "legacy" // default
	if a.Spec.IsOAS && a.Spec.OAS.GetTykExtension() != nil {
		if auth := a.Spec.OAS.GetTykExtension().Server.Authentication; auth != nil && auth.SecurityProcessingMode != "" {
			processingMode = auth.SecurityProcessingMode
		}
	}

	// Single or no requirements: always use AND logic
	if len(a.Spec.SecurityRequirements) <= 1 {

		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	if processingMode == "" || processingMode == "legacy" {

		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	// Compliant mode with multiple requirements: Use OR logic

	var lastError error
	var lastCode int

	for _, mw := range a.authMiddlewares {

		// Clone the request to avoid side effects from failed auth attempts
		// Each middleware gets a clean request without modifications from previous attempts
		rClone := r.Clone(r.Context())

		err, code := mw.ProcessRequest(w, rClone, nil)
		if err == nil {

			if session := ctxGetSession(rClone); session != nil {
				ctxSetSession(r, session, false, a.Gw.GetConfig().HashKeys)
			}

			// Copy any other important context values from the successful attempt back to the original request
			*r = *rClone

			return nil, http.StatusOK
		}

		lastError = err
		lastCode = code
	}

	return lastError, lastCode
}

// Name returns the name of the middleware
func (a *AuthORWrapper) Name() string {
	return "AuthORWrapper"
}

// EnabledForSpec checks if the middleware is enabled for the API spec
func (a *AuthORWrapper) EnabledForSpec() bool {
	// AuthORWrapper is only used when there are multiple security requirements
	// or when we need special processing. With a single requirement,
	// the auth middlewares are added directly to the chain.
	return len(a.Spec.SecurityRequirements) > 1 && len(a.authMiddlewares) > 1
}

// Init initializes the AuthORWrapper middleware
func (a *AuthORWrapper) Init() {
	spec := a.Spec

	a.authMiddlewares = []TykMiddleware{}

	if spec.EnableJWT {
		jwtMw := &JWTMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		jwtMw.Spec = spec
		jwtMw.Gw = a.Gw
		jwtMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, jwtMw)
	}

	if spec.UseBasicAuth {
		basicMw := &BasicAuthKeyIsValid{BaseMiddleware: a.BaseMiddleware.Copy()}
		basicMw.Spec = spec
		basicMw.Gw = a.Gw
		basicMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, basicMw)
	}

	if spec.EnableSignatureChecking {
		hmacMw := &HTTPSignatureValidationMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		hmacMw.Spec = spec
		hmacMw.Gw = a.Gw
		hmacMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, hmacMw)
	}

	if spec.UseOauth2 {
		oauthMw := &Oauth2KeyExists{BaseMiddleware: a.BaseMiddleware.Copy()}
		oauthMw.Spec = spec
		oauthMw.Gw = a.Gw
		oauthMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, oauthMw)
	}

	// Always add standard auth (API key) if enabled or as fallback
	if spec.UseStandardAuth || len(a.authMiddlewares) == 0 {
		authKeyMw := &AuthKey{BaseMiddleware: a.BaseMiddleware.Copy()}
		authKeyMw.Spec = spec
		authKeyMw.Gw = a.Gw
		authKeyMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, authKeyMw)
	}

}
