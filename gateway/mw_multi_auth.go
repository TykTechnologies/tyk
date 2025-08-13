package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/user"
)

// MultiAuthMiddleware handles OR authentication conditions where multiple
// security requirements are tried sequentially until one succeeds.
type MultiAuthMiddleware struct {
	BaseMiddleware
	authRequirements []AuthRequirement
}

// AuthRequirement represents one authentication requirement with its middleware chain
type AuthRequirement struct {
	Name        string
	Schemes     map[string][]string
	Middlewares []TykMiddleware
}

// Name returns the middleware name
func (m *MultiAuthMiddleware) Name() string {
	return "MultiAuthMiddleware"
}

// EnabledForSpec checks if multi-auth is enabled for this API
func (m *MultiAuthMiddleware) EnabledForSpec() bool {
	if m.Spec.IsOAS {
		if auth := m.Spec.OAS.GetTykExtension().Server.Authentication; auth != nil && auth.MultiAuth != nil {
			return auth.MultiAuth.Enabled
		}
	}
	return false
}

// ProcessRequest implements the OR authentication logic
func (m *MultiAuthMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := m.Logger()
	var authErrors []string

	// Try each authentication requirement until one succeeds
	for i, requirement := range m.authRequirements {
		logger.Debugf("Trying authentication requirement %d: %s", i, requirement.Name)

		// Try all middleware in this requirement (AND logic within requirement)
		authSuccess := true
		var lastError error
		var session *user.SessionState

		for _, middleware := range requirement.Middlewares {
			err, _ := middleware.ProcessRequest(w, r, nil)
			if err != nil {
				authSuccess = false
				lastError = err
				logger.Debugf("Auth middleware %s failed: %v", middleware.Name(), err)
				break
			}

			// If this middleware succeeded, capture the session
			if session == nil {
				session = ctxGetSession(r)
			}
		}

		if authSuccess {
			logger.Infof("Authentication successful using requirement %d: %s", i, requirement.Name)

			// Store which auth method succeeded for analytics/logging
			r.Header.Set("X-Tyk-Auth-Method", requirement.Name)

			// Set the base identity provider based on successful method
			m.setBaseIdentityProvider(requirement)

			return nil, http.StatusOK
		}

		// Log the failure for this requirement
		errorMsg := fmt.Sprintf("Requirement %d (%s): %v", i, requirement.Name, lastError)
		authErrors = append(authErrors, errorMsg)
		logger.Debugf("Authentication requirement %d failed: %v", i, lastError)

		// Clear any partial session state from failed attempt
		ctxSetSession(r, nil, false, m.Gw.GetConfig().HashKeys)
	}

	// All authentication requirements failed
	logger.Info("All authentication requirements failed")

	// Create aggregated error message
	aggregatedError := fmt.Sprintf("Authentication failed. Tried %d methods: %s",
		len(authErrors), strings.Join(authErrors, "; "))

	return errors.New(aggregatedError), http.StatusUnauthorized
}

// setBaseIdentityProvider determines the base identity provider based on the successful auth method
func (m *MultiAuthMiddleware) setBaseIdentityProvider(requirement AuthRequirement) {
	if m.Spec.IsOAS {
		auth := m.Spec.OAS.GetTykExtension().Server.Authentication
		if auth != nil && auth.MultiAuth != nil {
			// Determine base identity provider from the successful requirement
			for schemeName := range requirement.Schemes {
				switch schemeName {
				case "apiKey":
					auth.MultiAuth.BaseIdentityProvider = "auth_token"
				case "jwt":
					auth.MultiAuth.BaseIdentityProvider = "jwt_claim"
				case "basic":
					auth.MultiAuth.BaseIdentityProvider = "basic_auth_user"
				case "oauth2":
					auth.MultiAuth.BaseIdentityProvider = "oauth_key"
				case "hmac":
					auth.MultiAuth.BaseIdentityProvider = "hmac_key"
				}
				break // Use first scheme to determine provider
			}
		}
	}
}

// BuildAuthRequirements creates authentication requirements from OAS multi-auth config
func (m *MultiAuthMiddleware) BuildAuthRequirements(gw *Gateway, spec *APISpec, baseMid *BaseMiddleware) {
	if !m.EnabledForSpec() {
		return
	}

	auth := spec.OAS.GetTykExtension().Server.Authentication
	if auth == nil || auth.MultiAuth == nil {
		return
	}

	logger := m.Logger()
	logger.Infof("Building %d authentication requirements", len(auth.MultiAuth.Requirements))

	for i, req := range auth.MultiAuth.Requirements {
		authReq := AuthRequirement{
			Name:        fmt.Sprintf("requirement_%d", i),
			Schemes:     req.Schemes,
			Middlewares: make([]TykMiddleware, 0),
		}

		// Build middleware chain for this requirement
		for schemeName := range req.Schemes {
			middleware := m.createAuthMiddleware(schemeName, gw, spec, baseMid)
			if middleware != nil {
				authReq.Middlewares = append(authReq.Middlewares, middleware)
				logger.Debugf("Added %s middleware to requirement %d", schemeName, i)
			}
		}

		if len(authReq.Middlewares) > 0 {
			m.authRequirements = append(m.authRequirements, authReq)
			logger.Debugf("Created auth requirement %d with %d middleware(s)", i, len(authReq.Middlewares))
		}
	}
}

// createAuthMiddleware creates the appropriate middleware for a given scheme
func (m *MultiAuthMiddleware) createAuthMiddleware(schemeName string, gw *Gateway, spec *APISpec, baseMid *BaseMiddleware) TykMiddleware {
	switch schemeName {
	case "apiKey":
		if spec.UseStandardAuth {
			return &AuthKey{BaseMiddleware: baseMid.Copy()}
		}
	case "jwt":
		if spec.EnableJWT {
			return &JWTMiddleware{BaseMiddleware: baseMid.Copy()}
		}
	case "basic":
		if spec.UseBasicAuth {
			return &BasicAuthKeyIsValid{BaseMiddleware: baseMid.Copy()}
		}
	case "oauth2":
		if spec.UseOauth2 {
			return &Oauth2KeyExists{BaseMiddleware: baseMid.Copy()}
		}
	case "hmac":
		if spec.EnableSignatureChecking {
			return &HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid.Copy()}
		}
	}

	m.Logger().Warnf("No middleware found for scheme: %s", schemeName)
	return nil
}
