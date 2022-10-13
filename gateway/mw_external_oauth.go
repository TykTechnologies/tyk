package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pmylund/go-cache"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type ExternalOAuthMiddleware struct {
	BaseMiddleware
	jwkCache *cache.Cache
}

func (k *ExternalOAuthMiddleware) Name() string {
	return "ExternalOAuth"
}

func (k *ExternalOAuthMiddleware) EnabledForSpec() bool {
	return k.Spec.ExternalOAuth.Enabled
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *ExternalOAuthMiddleware) getAuthType() string {
	return apidef.ExternalOAuthType
}

func (k *ExternalOAuthMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	token, _ := k.getAuthToken(k.getAuthType(), r)
	if token == "" {
		return errors.New("authorization field missing"), http.StatusBadRequest
	}

	token = stripBearer(token)

	var (
		valid      bool
		err        error
		identifier string
	)

	if len(k.Spec.ExternalOAuth.Providers) == 0 {
		return errors.New("there should be at least one provider configured"), http.StatusNotFound
	}

	// Just the first one will be used, later there can be multiple providers supported
	provider := k.Spec.ExternalOAuth.Providers[0]

	if provider.JWT.Enabled {
		valid, identifier, err = k.jwt(token, provider.JWT)
	} else if provider.Introspection.Enabled {
		valid, identifier, err = k.introspection(token)
	} else {
		return errors.New("access token validation method is not specified"), http.StatusInternalServerError
	}

	if err != nil {
		return errors.New("error happened during the access token validation"), http.StatusInternalServerError
	}

	if !valid {
		return errors.New("access token is not valid"), http.StatusUnauthorized
	}

	var virtualSession user.SessionState
	virtualSession, exists := k.CheckSessionAndIdentityForValidKey(identifier, r)
	if !exists {
		virtualSession = k.generateVirtualSessionFor(r, identifier)
	}

	ctxSetSession(r, &virtualSession, false, k.Gw.GetConfig().HashKeys)

	// Request is valid, carry on
	return nil, http.StatusOK
}

// jwt makes access token validation without making a network call and validates access token locally.
// The access token should be JWT type.
func (k *ExternalOAuthMiddleware) jwt(accessToken string, jwtValidation apidef.JWTValidation) (bool, string, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	// Verify the token
	token, err := parser.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if err := assertSigningMethod(k.Spec.JWTSigningMethod, token); err != nil {
			return nil, err
		}

		val, err := k.getSecretFromJWKOrConfig()
		if err != nil {
			k.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}

		return parseJWTKey(k.Spec.JWTSigningMethod, val)
	})

	if err != nil || (token != nil && !token.Valid) {
		return false, "", fmt.Errorf("invalid token: %w", err)
	}

	if jwtErr := timeValidateJWTClaims(token.Claims.(jwt.MapClaims), jwtValidation.ExpiresAtValidationSkew,
		jwtValidation.IssuedAtValidationSkew, jwtValidation.NotBeforeValidationSkew); jwtErr != nil {
		return false, "", fmt.Errorf("key not authorized: %w", jwtErr)
	}

	userId, err := getUserIdFromClaim(token.Claims.(jwt.MapClaims), jwtValidation.IdentityBaseField)

	if err != nil {
		return false, "", err
	}

	return true, userId, nil
}

// getSecretFromJWKOrConfig gets the secret to verify jwt signature from API definition
// or from JWK set if config is set to a URL
func (k *ExternalOAuthMiddleware) getSecretFromJWKOrConfig() (interface{}, error) {
	if k.jwkCache == nil {
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	// is it a JWK URL?
	if httpScheme.MatchString(k.Spec.JWTSource) {
		return getJWK(k.Spec.JWTSource, k.Spec.APIID, k.Gw.GetConfig().JWTSSLInsecureSkipVerify, k.jwkCache)
	}

	decodedCert, err := base64.StdEncoding.DecodeString(k.Spec.JWTSource)
	if err != nil {
		return nil, err
	}

	// is decoded a JWK url too?
	if httpScheme.MatchString(string(decodedCert)) {
		return getJWK(string(decodedCert), k.Spec.APIID, k.Gw.GetConfig().JWTSSLInsecureSkipVerify, k.jwkCache)
	}

	return decodedCert, nil
}

// introspection makes an introspection request to third-party provider to check whether the access token is valid or not.
// The access token can be both JWT and opaque type.
func (k *ExternalOAuthMiddleware) introspection(accessToken string) (bool, string, error) {
	return false, "", errors.New("introspection not implemented yet")
}

// generateVirtualSessionFor generates a virtual session for the given access token by using its identifier.
func (k *ExternalOAuthMiddleware) generateVirtualSessionFor(r *http.Request, identifier string) user.SessionState {
	return user.SessionState{}
}
