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
	logger := a.Logger()
	logger.Debugf("OR wrapper processing with %d middlewares, %d security requirements, mode: %s",
		len(a.authMiddlewares), len(a.Spec.SecurityRequirements), a.Spec.SecurityProcessingMode)

	// Determine processing mode
	processingMode := a.Spec.SecurityProcessingMode
	if processingMode == "" {
		processingMode = "legacy"
	}

	// Legacy mode: Always use AND logic regardless of SecurityRequirements
	// This maintains backward compatibility
	if processingMode == "legacy" || len(a.Spec.SecurityRequirements) <= 1 {
		if processingMode == "legacy" {
			logger.Debug("Using AND logic (legacy mode)")
		} else {
			logger.Debug("Using AND logic (single or no security requirement)")
		}
		
		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	// Compliant mode with multiple requirements: Use OR logic
	logger.Debugf("Using OR logic (compliant mode) with %d auth middlewares", len(a.authMiddlewares))

	var lastError error
	var lastCode int

	for i, mw := range a.authMiddlewares {
		logger.Debugf("Trying auth middleware %d: %T", i, mw)

		// Clone the request to avoid side effects from failed auth attempts
		// Each middleware gets a clean request without modifications from previous attempts
		rClone := r.Clone(r.Context())

		err, code := mw.ProcessRequest(w, rClone, nil)
		if err == nil {
			logger.Debugf("Auth middleware %d succeeded", i)

			if session := ctxGetSession(rClone); session != nil {
				ctxSetSession(r, session, false, a.Gw.GetConfig().HashKeys)
			}

			// Copy any other important context values from the successful attempt back to the original request
			*r = *rClone

			return nil, http.StatusOK
		}

		logger.Debugf("Auth middleware %d failed: %v (code: %d)", i, err, code)

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
	logger := a.Logger()
	spec := a.Spec

	a.authMiddlewares = []TykMiddleware{}

	if spec.EnableJWT {
		logger.Debug("Adding JWT middleware to OR wrapper")
		jwtMw := &JWTMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		jwtMw.Spec = spec
		jwtMw.Gw = a.Gw
		jwtMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, jwtMw)
	}

	if spec.UseBasicAuth {
		logger.Debug("Adding Basic Auth middleware to OR wrapper")
		basicMw := &BasicAuthKeyIsValid{BaseMiddleware: a.BaseMiddleware.Copy()}
		basicMw.Spec = spec
		basicMw.Gw = a.Gw
		basicMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, basicMw)
	}

	if spec.EnableSignatureChecking {
		logger.Debug("Adding HMAC middleware to OR wrapper")
		hmacMw := &HTTPSignatureValidationMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		hmacMw.Spec = spec
		hmacMw.Gw = a.Gw
		hmacMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, hmacMw)
	}

	if spec.UseOauth2 {
		logger.Debug("Adding OAuth middleware to OR wrapper")
		oauthMw := &Oauth2KeyExists{BaseMiddleware: a.BaseMiddleware.Copy()}
		oauthMw.Spec = spec
		oauthMw.Gw = a.Gw
		oauthMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, oauthMw)
	}

	// Always add standard auth (API key) if enabled or as fallback
	if spec.UseStandardAuth || len(a.authMiddlewares) == 0 {
		logger.Debug("Adding API Key middleware to OR wrapper")
		authKeyMw := &AuthKey{BaseMiddleware: a.BaseMiddleware.Copy()}
		authKeyMw.Spec = spec
		authKeyMw.Gw = a.Gw
		authKeyMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, authKeyMw)
	}

	logger.Debugf("AuthORWrapper.Init completed with %d middlewares", len(a.authMiddlewares))
}
