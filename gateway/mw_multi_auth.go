package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	ErrMultiAuthAllFailed = "multiauth.all_failed"
	MsgMultiAuthAllFailed = "All authentication methods failed"
)

// MultiAuthMiddleware handles OR authentication conditions where multiple
// security requirements are tried sequentially until one succeeds.
type MultiAuthMiddleware struct {
	*BaseMiddleware
	authRequirements []AuthRequirement
}

// AuthRequirement represents one authentication requirement with its middleware chain.
type AuthRequirement struct {
	Name        string
	Schemes     map[string][]string
	Middlewares []TykMiddleware
	AuthType    apidef.AuthTypeEnum
}

// Name returns the middleware name.
func (m *MultiAuthMiddleware) Name() string {
	return "MultiAuthMiddleware"
}

// EnabledForSpec checks if multi-auth is enabled for this API.
func (m *MultiAuthMiddleware) EnabledForSpec() bool {
	if m.Spec.IsOAS {
		if auth := m.Spec.OAS.GetTykExtension().Server.Authentication; auth != nil && auth.MultiAuth != nil {
			return auth.MultiAuth.Enabled
		}
	}
	return false
}

// Init initializes the middleware.
func (m *MultiAuthMiddleware) Init() {
	if !m.EnabledForSpec() {
		return
	}

	// Initialize authentication requirements from OAS configuration
	if auth := m.Spec.OAS.GetTykExtension().Server.Authentication; auth != nil && auth.MultiAuth != nil {
		m.authRequirements = make([]AuthRequirement, 0, len(auth.MultiAuth.Requirements))

		for _, req := range auth.MultiAuth.Requirements {
			authReq := AuthRequirement{
				Name:        req.Name,
				Schemes:     req.Schemes,
				Middlewares: []TykMiddleware{},
			}

			// Build middleware chain for this requirement
			authReq.AuthType = m.buildMiddlewareChain(&authReq)

			m.authRequirements = append(m.authRequirements, authReq)
		}
	}
}

// buildMiddlewareChain creates middleware instances for a specific auth requirement.
func (m *MultiAuthMiddleware) buildMiddlewareChain(authReq *AuthRequirement) apidef.AuthTypeEnum {
	var primaryAuthType apidef.AuthTypeEnum = apidef.AuthTypeNone

	for schemeName := range authReq.Schemes {
		if m.Spec.IsOAS {
			if securityScheme := m.Spec.OAS.Components.SecuritySchemes[schemeName]; securityScheme != nil {
				schemeValue := securityScheme.Value
				if schemeValue != nil {
					switch {
					case schemeValue.Type == "apiKey":
						middleware := &AuthKey{BaseMiddleware: m.BaseMiddleware.Copy()}
						// Configure the middleware to use the specific auth config for this scheme
						if authConfig, exists := m.Spec.AuthConfigs[schemeName]; exists {
							middleware.Spec.AuthConfigs = map[string]apidef.AuthConfig{
								schemeName: authConfig,
							}
							middleware.Spec.Auth = authConfig
						}
						middleware.Spec.BaseIdentityProvidedBy = apidef.AuthToken
						middleware.Init()
						authReq.Middlewares = append(authReq.Middlewares, middleware)
						if primaryAuthType == apidef.AuthTypeNone {
							primaryAuthType = apidef.AuthToken
						}
					case schemeValue.Type == "http" && schemeValue.Scheme == "basic":
						middleware := &BasicAuthKeyIsValid{BaseMiddleware: m.BaseMiddleware.Copy()}
						if authConfig, exists := m.Spec.AuthConfigs[schemeName]; exists {
							middleware.Spec.AuthConfigs = map[string]apidef.AuthConfig{
								schemeName: authConfig,
							}
							middleware.Spec.Auth = authConfig
							middleware.Spec.UseBasicAuth = true
							middleware.Spec.BasicAuth = m.Spec.BasicAuth
						} else {
							// Create default basic auth config
							defaultConfig := apidef.AuthConfig{
								Name:          schemeName,
								DisableHeader: false,
							}
							middleware.Spec.AuthConfigs = map[string]apidef.AuthConfig{
								schemeName: defaultConfig,
							}
							middleware.Spec.Auth = defaultConfig
							middleware.Spec.UseBasicAuth = true
							middleware.Spec.BasicAuth = m.Spec.BasicAuth
						}
						middleware.Spec.BaseIdentityProvidedBy = apidef.BasicAuthUser
						middleware.Spec.UseBasicAuth = true
						middleware.Init()
						authReq.Middlewares = append(authReq.Middlewares, middleware)
						if primaryAuthType == apidef.AuthTypeNone {
							primaryAuthType = apidef.BasicAuthUser
						}
					case schemeValue.Type == "http" && schemeValue.Scheme == "bearer":
						if schemeValue.BearerFormat == "JWT" {
							middleware := &JWTMiddleware{BaseMiddleware: m.BaseMiddleware.Copy()}
							middleware.Init()
							authReq.Middlewares = append(authReq.Middlewares, middleware)
							if primaryAuthType == apidef.AuthTypeNone {
								primaryAuthType = apidef.JWTClaim
							}
						}
					case schemeValue.Type == "oauth2":
						middleware := &Oauth2KeyExists{BaseMiddleware: m.BaseMiddleware.Copy()}
						middleware.Init()
						authReq.Middlewares = append(authReq.Middlewares, middleware)
						if primaryAuthType == apidef.AuthTypeNone {
							primaryAuthType = apidef.OAuthKey
						}
					}
				}
			}
		}
	}

	return primaryAuthType
}

// ProcessRequest implements the OR authentication logic.
func (m *MultiAuthMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ any) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	var authErrors []string

	// Try each authentication requirement until one succeeds
	for i, requirement := range m.authRequirements {

		authSuccess := true
		var lastError error

		for _, middleware := range requirement.Middlewares {
			err, _ := middleware.ProcessRequest(w, r, nil)
			if err != nil {
				authSuccess = false
				lastError = err
				break
			}

			currentSession := ctxGetSession(r)
			if currentSession == nil && middleware.Name() == "AuthKey" {
				authHeaderValue := r.Header.Get("Authorization")
				if authHeaderValue != "" {
					key := strings.TrimPrefix(authHeaderValue, "Bearer ")
					key = strings.TrimSpace(key)
					if key != "" {
						gw := m.Gw
						loadedSession, keyExists := gw.GlobalSessionManager.SessionDetail(m.Spec.OrgID, key, false)
						if keyExists {
							ctxSetSession(r, &loadedSession, false, gw.GetConfig().HashKeys)
						}
					}
				}
			}
		}

		if authSuccess {
			r.Header.Set("X-Tyk-Auth-Method", requirement.Name)
			m.setBaseIdentityProvider(r, requirement.AuthType)
			ctxSetRequestStatus(r, StatusOkAndIgnore)
			return nil, http.StatusOK
		}

		errorMsg := fmt.Sprintf("Requirement %d (%s): %v", i, requirement.Name, lastError)
		authErrors = append(authErrors, errorMsg)
	}

	// Return standard authentication error message for backward compatibility
	// Always return the last error message to maintain consistency with single auth behavior
	if len(authErrors) > 0 {
		lastError := authErrors[len(authErrors)-1]
		// Extract the actual error message (remove requirement prefix)
		colonIndex := strings.Index(lastError, ": ")
		if colonIndex >= 0 {
			return fmt.Errorf("%v", lastError[colonIndex+2:]), http.StatusUnauthorized
		}
		return fmt.Errorf("%v", lastError), http.StatusUnauthorized
	}

	// Fallback error if no auth errors were captured
	return fmt.Errorf(MsgApiAccessDisallowed), http.StatusUnauthorized
}

// setBaseIdentityProvider sets the BaseIdentityProvider in the request context.
func (m *MultiAuthMiddleware) setBaseIdentityProvider(r *http.Request, authType apidef.AuthTypeEnum) {
	ctx := context.WithValue(r.Context(), "multiauth_successful_type", authType)
	*r = *r.WithContext(ctx)
}

// Config returns the middleware configuration.
func (m *MultiAuthMiddleware) Config() (any, error) {
	return nil, nil
}

// Unload performs cleanup when the middleware is unloaded.
func (m *MultiAuthMiddleware) Unload() {
	for _, requirement := range m.authRequirements {
		for _, middleware := range requirement.Middlewares {
			middleware.Unload()
		}
	}
}
