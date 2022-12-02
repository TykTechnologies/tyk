package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pmylund/go-cache"
	"github.com/square/go-jose"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

var (
	externalOAuthJWKCache           *cache.Cache
	externalOAuthIntrospectionCache *introspectionCache
	ErrTokenValidationFailed        = errors.New("error happened during the access token validation")
	ErrKIDNotAString                = errors.New("kid is not a string")
	ErrNoMatchingKIDFound           = errors.New("no matching KID could be found")
)

type ExternalOAuthMiddleware struct {
	BaseMiddleware
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
		valid, identifier, err = k.jwt(token)
	} else if provider.Introspection.Enabled {
		valid, identifier, err = k.introspection(token)
	} else {
		return errors.New("access token validation method is not specified"), http.StatusInternalServerError
	}

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrSignatureInvalid), errors.Is(err, jwt.ErrTokenMalformed), errors.Is(err, jwt.ErrTokenNotValidYet),
			errors.Is(err, jwt.ErrTokenUsedBeforeIssued), errors.Is(err, jwt.ErrTokenExpired):
			return err, http.StatusUnauthorized
		}

		return ErrTokenValidationFailed, http.StatusInternalServerError
	}

	if !valid {
		return errors.New("access token is not valid"), http.StatusUnauthorized
	}

	sessionID := k.generateSessionID(identifier)

	k.Logger().Debug("External OAuth Temporary session ID is: ", sessionID)

	// CheckSessionAndIdentityForValidKey returns a session with keyID populated
	var virtualSession user.SessionState
	virtualSession, exists := k.CheckSessionAndIdentityForValidKey(sessionID, r)
	if !exists {
		virtualSession = k.generateVirtualSessionFor(r, sessionID)
	}

	ctxSetSession(r, &virtualSession, false, k.Gw.GetConfig().HashKeys)

	// Request is valid, carry on
	return nil, http.StatusOK
}

// jwt makes access token validation without making a network call and validates access token locally.
// The access token should be JWT type.
func (k *ExternalOAuthMiddleware) jwt(accessToken string) (bool, string, error) {
	jwtValidation := k.Spec.ExternalOAuth.Providers[0].JWT
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	// Verify the token
	token, err := parser.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// don't forget to validate the alg is what you expect:
		if err := assertSigningMethod(jwtValidation.SigningMethod, token); err != nil {
			return nil, err
		}

		val, err := k.getSecretFromJWKOrConfig(token.Header[KID], jwtValidation)
		if err != nil {
			k.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}

		return parseJWTKey(jwtValidation.SigningMethod, val)
	})

	if err != nil {
		return false, "", fmt.Errorf("token verification failed: %w", err)
	}

	if token != nil && !token.Valid {
		return false, "", errors.New("invalid token")
	}

	if err := timeValidateJWTClaims(token.Claims.(jwt.MapClaims), jwtValidation.ExpiresAtValidationSkew,
		jwtValidation.IssuedAtValidationSkew, jwtValidation.NotBeforeValidationSkew); err != nil {
		return false, "", fmt.Errorf("key not authorized: %w", err)
	}

	var userID string
	userID, err = getUserIDFromClaim(token.Claims.(jwt.MapClaims), jwtValidation.IdentityBaseField)
	if err != nil {
		return false, "", err
	}

	return true, userID, nil
}

// getSecretFromJWKURL gets the secret to verify jwt signature from a JWK URL.
func (k *ExternalOAuthMiddleware) getSecretFromJWKURL(url string, kid interface{}) (interface{}, error) {
	kidStr, ok := kid.(string)
	if !ok {
		return nil, ErrKIDNotAString
	}

	if externalOAuthJWKCache == nil {
		externalOAuthJWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var (
		jwkSet *jose.JSONWebKeySet
		err    error
	)

	cachedJWK, found := externalOAuthJWKCache.Get(k.Spec.APIID)
	if !found {
		if jwkSet, err = getJWK(url, k.Gw.GetConfig().JWTSSLInsecureSkipVerify); err != nil {
			return nil, err
		}

		k.Logger().Debug("Caching JWK")
		externalOAuthJWKCache.Set(k.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(*jose.JSONWebKeySet)
	}

	k.Logger().Debug("Checking JWKs...")
	if keys := jwkSet.Key(kidStr); len(keys) > 0 {
		return keys[0].Key, nil
	}

	return nil, ErrNoMatchingKIDFound
}

// getSecretFromJWKOrConfig gets the secret to verify jwt signature from API definition
// or from JWK set if config is set to a URL
func (k *ExternalOAuthMiddleware) getSecretFromJWKOrConfig(kid interface{}, jwtValidation apidef.JWTValidation) (interface{}, error) {
	// is it a JWK URL?
	if httpScheme.MatchString(jwtValidation.Source) {
		return k.getSecretFromJWKURL(jwtValidation.Source, kid)
	}

	decodedSource, err := base64.StdEncoding.DecodeString(jwtValidation.Source)
	if err != nil {
		return nil, err
	}

	// is decoded a JWK url too?
	if httpScheme.MatchString(string(decodedSource)) {
		return k.getSecretFromJWKURL(string(decodedSource), kid)
	}

	return decodedSource, nil
}

// introspection makes an introspection request to third-party provider to check whether the access token is valid or not.
// The access token can be both JWT and opaque type.
func (k *ExternalOAuthMiddleware) introspection(accessToken string) (bool, string, error) {
	opts := k.Spec.ExternalOAuth.Providers[0].Introspection

	var (
		claims jwt.MapClaims
		cached bool
		err    error
	)

	if opts.Cache.Enabled {
		if externalOAuthIntrospectionCache == nil {
			externalOAuthIntrospectionCache = newIntrospectionCache(k.Gw)
		}

		claims, cached = externalOAuthIntrospectionCache.GetRes(accessToken)
	}

	if !cached {
		log.WithError(err).Debug("Doing OAuth introspection call")
		claims, err = introspect(opts, accessToken)
		if err != nil {
			return false, "", fmt.Errorf("introspection err: %s", err)
		}

		if opts.Cache.Enabled {
			err = externalOAuthIntrospectionCache.SetRes(accessToken, claims, opts.Cache.Timeout)
			if err != nil {
				log.WithError(err).Debug("OAuth introspection caching is enabled but the result couldn't be cached in redis")
			}
		}
	} else {
		log.WithError(err).Debug("Found OAuth introspection result in the redis cache")

		if isExpired(claims) {
			return false, "", jwt.ErrTokenExpired
		}
	}

	active, ok := claims["active"]
	if !ok {
		return false, "", errors.New("introspection result doesn't have active flag")
	}

	if !active.(bool) {
		return false, "", nil
	}

	userID, err := getUserIDFromClaim(claims, opts.IdentityBaseField)
	if err != nil {
		return false, "", err
	}

	return true, userID, nil
}

// generateVirtualSessionFor generates a virtual session for the given access token by using its identifier.
func (k *ExternalOAuthMiddleware) generateVirtualSessionFor(r *http.Request, sessionID string) user.SessionState {
	virtualSession := *CreateStandardSession()
	virtualSession.KeyID = sessionID
	virtualSession.OrgID = k.Spec.OrgID
	virtualSession.AccessRights = map[string]user.AccessDefinition{
		k.Spec.APIID: {
			Limit: user.APILimit{},
		},
	}
	return virtualSession
}

func isExpired(claims jwt.MapClaims) bool {
	exp, ok := claims["exp"]
	if !ok {
		return false
	}

	// casting to float64 because json.Unmarshal function builds numbers as float64
	expVal, casted := exp.(float64)
	if casted && time.Now().After(time.Unix(int64(expVal), 0)) {
		return true
	}

	return false
}

func newIntrospectionCache(gw *Gateway) *introspectionCache {
	return &introspectionCache{RedisCluster: storage.RedisCluster{KeyPrefix: "introspection-", RedisController: gw.RedisController}}
}

type introspectionCache struct {
	storage.RedisCluster
}

func (c *introspectionCache) GetRes(token string) (jwt.MapClaims, bool) {
	var claims jwt.MapClaims
	claimsStr, err := c.GetKey(token)
	if err != nil {
		return nil, false
	}

	err = json.Unmarshal([]byte(claimsStr), &claims)
	if err != nil {
		return nil, false
	}

	return claims, true
}

func (c *introspectionCache) SetRes(token string, res jwt.MapClaims, timeout int64) error {
	claimsInBytes, err := json.Marshal(res)
	if err != nil {
		return err
	}

	return c.SetKey(token, string(claimsInBytes), timeout)
}

func introspect(opts apidef.Introspection, accessToken string) (jwt.MapClaims, error) {
	body := url.Values{}
	body.Set("token", accessToken)
	body.Set("client_id", opts.ClientID)
	body.Set("client_secret", opts.ClientSecret)

	res, err := http.Post(opts.URL, "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error happened during the introspection call: %s", err)
	}

	defer res.Body.Close()

	bodyInBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("couldn't read the introspection call response: %s", err)
	}

	var claims jwt.MapClaims
	err = json.Unmarshal(bodyInBytes, &claims)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal the introspection call response: %s", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status does not indicate success: code: %d, body: %v", res.StatusCode, res.Body)
	}

	return claims, nil
}
