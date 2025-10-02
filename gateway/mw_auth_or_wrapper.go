package gateway

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

type AuthORWrapper struct {
	BaseMiddleware
	authMiddlewares []TykMiddleware
}

func (a *AuthORWrapper) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
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

		rClone := r.Clone(r.Context())
		groupSuccess := true
		var groupError error
		var groupCode int

		for _, schemeName := range requirement {
			mw := a.getMiddlewareForScheme(schemeName)
			if mw == nil {
				a.Logger().Debugf("OR wrapper: no middleware found for scheme %s, skipping group", schemeName)
				groupSuccess = false
				groupError = lastError
				groupCode = lastCode
				break
			}

			a.Logger().Debugf("OR wrapper: executing auth method %s in group %d", mw.Name(), groupIdx+1)
			err, code := mw.ProcessRequest(w, rClone, nil)
			if err != nil {
				a.Logger().Debugf("OR wrapper: auth method %s failed with error: %v (code: %d)", mw.Name(), err, code)
				groupSuccess = false
				groupError = err
				groupCode = code
				break
			}
			a.Logger().Debugf("OR wrapper: auth method %s succeeded", mw.Name())
		}

		if groupSuccess {
			a.Logger().Debugf("OR wrapper: security requirement group %d succeeded", groupIdx+1)

			if session := ctxGetSession(rClone); session != nil {
				ctxSetSession(r, session, false, a.Gw.GetConfig().HashKeys)
			}

			*r = *rClone

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
			case scheme.Type == "http" && scheme.Scheme == "bearer" && scheme.BearerFormat == "JWT":
				return a.findMiddlewareByType(&JWTMiddleware{})
			case scheme.Type == "apiKey":
				return a.findMiddlewareByType(&AuthKey{})
			case scheme.Type == "http" && scheme.Scheme == "basic":
				return a.findMiddlewareByType(&BasicAuthKeyIsValid{})
			case scheme.Type == "oauth2":
				if a.Spec.ExternalOAuth.Enabled {
					return a.findMiddlewareByType(&ExternalOAuthMiddleware{})
				}
				return a.findMiddlewareByType(&Oauth2KeyExists{})
			}
		}
	}

	if tykExt := a.Spec.OAS.GetTykExtension(); tykExt != nil {
		if auth := tykExt.Server.Authentication; auth != nil && auth.SecuritySchemes != nil {
			if tykScheme := auth.SecuritySchemes[schemeName]; tykScheme != nil {
				if a.Spec.EnableSignatureChecking {
					return a.findMiddlewareByType(&HTTPSignatureValidationMiddleware{})
				}

				if a.Spec.UseOpenID {
					return a.findMiddlewareByType(&OpenIDMW{})
				}

				customPluginAuthEnabled := a.Spec.CustomPluginAuthEnabled || a.Spec.UseGoPluginAuth || a.Spec.EnableCoProcessAuth
				if customPluginAuthEnabled {
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
			}
		}
	}

	return nil
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

func (a *AuthORWrapper) EnabledForSpec() bool {
	return len(a.Spec.SecurityRequirements) > 1 && len(a.authMiddlewares) > 1
}

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

	if spec.UseStandardAuth || len(a.authMiddlewares) == 0 {
		authKeyMw := &AuthKey{BaseMiddleware: a.BaseMiddleware.Copy()}
		authKeyMw.Spec = spec
		authKeyMw.Gw = a.Gw
		authKeyMw.Init()
		a.authMiddlewares = append(a.authMiddlewares, authKeyMw)
	}

}
