package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/coprocess"
)

// OpenAPI security scheme constants
const (
	securitySchemeTypeHTTP   = "http"
	securitySchemeTypeAPIKey = "apiKey"
	securitySchemeTypeOAuth2 = "oauth2"

	securitySchemeHTTPBearer = "bearer"
	securitySchemeHTTPBasic  = "basic"

	securitySchemeBearerFormatJWT = "JWT"

	// Tyk vendor extension security scheme names
	securitySchemeNameHMAC   = "hmac"
	securitySchemeNameOIDC   = "oidc"
	securitySchemeNameCustom = "custom"
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
	processingMode := oas.SecurityProcessingModeLegacy
	if a.Spec.IsOAS && a.Spec.OAS.GetTykExtension() != nil {
		if auth := a.Spec.OAS.GetTykExtension().Server.Authentication; auth != nil && auth.SecurityProcessingMode != "" {
			processingMode = auth.SecurityProcessingMode
		}
	}

	if len(a.Spec.SecurityRequirements) <= 1 {
		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	if processingMode == "" || processingMode == oas.SecurityProcessingModeLegacy {
		for _, mw := range a.authMiddlewares {
			if err, code := mw.ProcessRequest(w, r, nil); err != nil {
				return err, code
			}
		}
		return nil, http.StatusOK
	}

	var lastError error
	var lastCode int

	for groupIdx, requirement := range a.Spec.SecurityRequirements {
		a.Logger().Debugf("OR wrapper: trying security requirement group %d/%d: %v", groupIdx+1, len(a.Spec.SecurityRequirements), requirement)

		groupSuccess := true
		var groupError error
		var groupCode int
		var lastSuccessfulClone *http.Request

		for _, schemeName := range requirement {
			mw := a.getMiddlewareForScheme(schemeName)
			if mw == nil {
				a.Logger().Warnf("OR wrapper: no middleware found for scheme %s (server misconfiguration), skipping group", schemeName)
				groupSuccess = false
				groupError = fmt.Errorf("security scheme %s is not configured", schemeName)
				groupCode = http.StatusInternalServerError
				break
			}

			a.Logger().Debugf("OR wrapper: executing auth method %s in group %d", mw.Name(), groupIdx+1)
			// Clone request per middleware to prevent mutations from affecting subsequent auth methods in the AND group
			rClone := r.Clone(r.Context())
			// Use a response recorder to prevent failed auth attempts from writing to the actual response
			recorder := httptest.NewRecorder()
			err, code := mw.ProcessRequest(recorder, rClone, nil)
			if err != nil {
				a.Logger().Debugf("OR wrapper: auth method %s failed with error: %v (code: %d)", mw.Name(), err, code)
				groupSuccess = false
				groupError = err
				groupCode = code
				break
			}
			a.Logger().Debugf("OR wrapper: auth method %s succeeded", mw.Name())
			lastSuccessfulClone = rClone
		}

		if groupSuccess {
			a.Logger().Debugf("OR wrapper: security requirement group %d succeeded", groupIdx+1)

			if session := ctxGetSession(lastSuccessfulClone); session != nil {
				ctxSetSession(r, session, false, a.Gw.GetConfig().HashKeys)
			}

			*r = *lastSuccessfulClone

			return nil, http.StatusOK
		}

		lastError = groupError
		lastCode = groupCode
	}

	return lastError, lastCode
}

func (a *AuthORWrapper) getMiddlewareForScheme(schemeName string) TykMiddleware {
	if !a.Spec.IsOAS {
		return nil
	}

	if a.Spec.OAS.T.Components != nil && a.Spec.OAS.T.Components.SecuritySchemes != nil {
		schemeRef := a.Spec.OAS.T.Components.SecuritySchemes[schemeName]
		if schemeRef != nil && schemeRef.Value != nil {
			scheme := schemeRef.Value

			switch {
			case scheme.Type == securitySchemeTypeHTTP && scheme.Scheme == securitySchemeHTTPBearer && scheme.BearerFormat == securitySchemeBearerFormatJWT:
				return a.findMiddlewareByType(&JWTMiddleware{})
			case scheme.Type == securitySchemeTypeAPIKey:
				return a.findMiddlewareByType(&AuthKey{})
			case scheme.Type == securitySchemeTypeHTTP && scheme.Scheme == securitySchemeHTTPBasic:
				return a.findMiddlewareByType(&BasicAuthKeyIsValid{})
			case scheme.Type == securitySchemeTypeOAuth2:
				if a.Spec.ExternalOAuth.Enabled {
					return a.findMiddlewareByType(&ExternalOAuthMiddleware{})
				}
				return a.findMiddlewareByType(&Oauth2KeyExists{})
			}
		}
	}

	// Check Tyk vendor extension authentication methods
	if tykExt := a.Spec.OAS.GetTykExtension(); tykExt != nil {
		if auth := tykExt.Server.Authentication; auth != nil {
			// First check if the scheme is defined in SecuritySchemes
			if auth.SecuritySchemes != nil {
				if tykScheme := auth.SecuritySchemes[schemeName]; tykScheme != nil {
					// Use type switch for standard auth types (JWT, Token, Basic, OAuth)
					// These can be reliably determined by their OAS type
					switch tykScheme.(type) {
					case *oas.JWT:
						return a.findMiddlewareByType(&JWTMiddleware{})
					case *oas.Token:
						return a.findMiddlewareByType(&AuthKey{})
					case *oas.Basic:
						return a.findMiddlewareByType(&BasicAuthKeyIsValid{})
					case *oas.OAuth:
						if a.Spec.ExternalOAuth.Enabled {
							return a.findMiddlewareByType(&ExternalOAuthMiddleware{})
						}
						return a.findMiddlewareByType(&Oauth2KeyExists{})
					}

					// For HMAC, OIDC, and Custom plugins, use legacy flag checks
					// This maintains backward compatibility with existing tests and configurations
					if a.Spec.EnableSignatureChecking {
						return a.findMiddlewareByType(&HTTPSignatureValidationMiddleware{})
					}

					if a.Spec.UseOpenID {
						return a.findMiddlewareByType(&OpenIDMW{})
					}

					middleware := a.findCustomPluginMiddleware()
					if middleware != nil {
						return middleware
					}
				}
			}

			// Fallback: check by scheme name even if not in SecuritySchemes
			// This handles cases where auth is enabled via direct fields (e.g., hmac.enabled: true)
			switch schemeName {
			case securitySchemeNameHMAC:
				if auth.HMAC != nil && auth.HMAC.Enabled && a.Spec.EnableSignatureChecking {
					return a.findMiddlewareByType(&HTTPSignatureValidationMiddleware{})
				}
			case securitySchemeNameOIDC:
				if auth.OIDC != nil && auth.OIDC.Enabled && a.Spec.UseOpenID {
					return a.findMiddlewareByType(&OpenIDMW{})
				}
			case securitySchemeNameCustom:
				if auth.Custom != nil && auth.Custom.Enabled {
					middleware := a.findCustomPluginMiddleware()
					if middleware != nil {
						return middleware
					}
				}
			}
		}
	}

	return nil
}

func (a *AuthORWrapper) findCustomPluginMiddleware() TykMiddleware {
	if a.isPluginAuthEnabled() {
		if mw := a.findMiddlewareByType(&GoPluginMiddleware{}); mw != nil {
			return mw
		}
		if mw := a.findMiddlewareByType(&CoProcessMiddleware{}); mw != nil {
			return mw
		}
		if mw := a.findMiddlewareByType(&DynamicMiddleware{}); mw != nil {
			return mw
		}
	}

	return nil
}

func (a *AuthORWrapper) isPluginAuthEnabled() bool {
	return a.Spec.CustomPluginAuthEnabled || a.Spec.UseGoPluginAuth || a.Spec.EnableCoProcessAuth
}

func (a *AuthORWrapper) findMiddlewareByType(example TykMiddleware) TykMiddleware {
	exampleType := fmt.Sprintf("%T", example)

	for _, mw := range a.authMiddlewares {
		if fmt.Sprintf("%T", mw) == exampleType {
			return mw
		}
	}
	return nil
}

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

	if spec.ExternalOAuth.Enabled {
		extOAuthMw := &ExternalOAuthMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		extOAuthMw.Spec = spec
		extOAuthMw.Gw = a.Gw
		extOAuthMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, extOAuthMw)
	}

	if spec.UseOpenID {
		openIDMw := &OpenIDMW{BaseMiddleware: a.BaseMiddleware.Copy()}
		openIDMw.Spec = spec
		openIDMw.Gw = a.Gw
		openIDMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, openIDMw)
	}

	if a.isPluginAuthEnabled() {
		a.initCustomPluginMiddleware()
	}

	if spec.UseStandardAuth || len(a.authMiddlewares) == 0 {
		authKeyMw := &AuthKey{BaseMiddleware: a.BaseMiddleware.Copy()}
		authKeyMw.Spec = spec
		authKeyMw.Gw = a.Gw
		authKeyMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, authKeyMw)
	}
}

func (a *AuthORWrapper) initCustomPluginMiddleware() {
	spec := a.Spec
	var mw TykMiddleware

	switch spec.CustomMiddleware.Driver {
	case apidef.OttoDriver:
		mw = &DynamicMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		dynamicMw, _ := mw.(*DynamicMiddleware)
		dynamicMw.MiddlewareClassName = spec.CustomMiddleware.AuthCheck.Name
		dynamicMw.Auth = true
	case apidef.GoPluginDriver:
		mw = &GoPluginMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		goPluginMw, _ := mw.(*GoPluginMiddleware)
		goPluginMw.Path = spec.CustomMiddleware.AuthCheck.Path
		goPluginMw.SymbolName = spec.CustomMiddleware.AuthCheck.Name
		goPluginMw.APILevel = true
	default:
		mw = &CoProcessMiddleware{BaseMiddleware: a.BaseMiddleware.Copy()}
		coProcessMw, _ := mw.(*CoProcessMiddleware)
		coProcessMw.HookType = coprocess.HookType_CustomKeyCheck
		coProcessMw.HookName = spec.CustomMiddleware.AuthCheck.Name
		coProcessMw.MiddlewareDriver = spec.CustomMiddleware.Driver
		coProcessMw.RawBodyOnly = spec.CustomMiddleware.AuthCheck.RawBodyOnly
	}

	mw.Init()

	if goPluginMw, ok := mw.(*GoPluginMiddleware); ok {
		goPluginMw.loadPlugin()
	}

	a.authMiddlewares = append(a.authMiddlewares, mw)
}
