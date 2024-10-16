package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	oauth2clientcredentials "golang.org/x/oauth2/clientcredentials"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	UpstreamOAuthErrorEventName = "UpstreamOAuthError"
	UpstreamOAuthMiddlewareName = "UpstreamOAuth"
)

type OAuthHeaderProvider interface {
	// getOAuthToken returns the OAuth token for the request.
	getOAuthToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error)
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

func newUpstreamOAuthClientCredentialsCache(connectionHandler *storage.ConnectionHandler) *upstreamOAuthClientCredentialsCache {
	return &upstreamOAuthClientCredentialsCache{RedisCluster: storage.RedisCluster{KeyPrefix: "upstreamOAuthCC-", ConnectionHandler: connectionHandler}}
}

type upstreamOAuthClientCredentialsCache struct {
	storage.RedisCluster
}

type UpstreamOAuthCache interface {
	// getToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error)
	// obtainToken issues a request to obtain the token from the OAuth provider.
	obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (*oauth2.Token, error)
}

// UpstreamOAuth is a middleware that will do basic authentication for upstream connections.
// UpstreamOAuth middleware is only supported in Tyk OAS API definitions.
type UpstreamOAuth struct {
	*BaseMiddleware
}

// Name returns the name of middleware.
func (OAuthSpec *UpstreamOAuth) Name() string {
	return UpstreamOAuthMiddlewareName
}

// EnabledForSpec returns true if the middleware is enabled based on API Spec.
func (OAuthSpec *UpstreamOAuth) EnabledForSpec() bool {
	if !OAuthSpec.Spec.UpstreamAuth.Enabled {
		return false
	}

	if !OAuthSpec.Spec.UpstreamAuth.OAuth.Enabled {
		return false
	}

	return true
}

// ProcessRequest will inject basic auth info into request context so that it can be used during reverse proxy.
func (OAuthSpec *UpstreamOAuth) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	oauthConfig := OAuthSpec.Spec.UpstreamAuth.OAuth

	upstreamOAuthProvider := UpstreamOAuthProvider{
		HeaderName: header.Authorization,
	}

	if oauthConfig.HeaderName != "" {
		upstreamOAuthProvider.HeaderName = oauthConfig.HeaderName
	}

	provider, err := getOAuthHeaderProvider(oauthConfig)
	if err != nil {
		return fmt.Errorf("failed to get OAuth header provider: %w", err), http.StatusInternalServerError
	}

	payload, err := provider.getOAuthToken(r, OAuthSpec)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err), http.StatusInternalServerError
	}

	upstreamOAuthProvider.AuthValue = payload

	httputil.SetUpstreamAuth(r, upstreamOAuthProvider)
	return nil, http.StatusOK
}

func getOAuthHeaderProvider(oauthConfig apidef.UpstreamOAuth) (OAuthHeaderProvider, error) {
	// to be extended when PasswordAuth is implemented
	return &ClientCredentialsOAuthProvider{}, nil
}

func (p *PerAPIClientCredentialsOAuthProvider) getOAuthHeaderValue(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	oauthConfig := OAuthSpec.Spec.UpstreamAuth.OAuth

	if oauthConfig.ClientCredentials.TokenProvider == nil {
		cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)
		tokenSource := cfg.TokenSource(r.Context())

		oauthConfig.ClientCredentials.TokenProvider = tokenSource
	}

	oauthToken, err := oauthConfig.ClientCredentials.TokenProvider.Token()
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	payload := fmt.Sprintf("Bearer %s", oauthToken.AccessToken)
	return payload, nil
}

func handleOAuthError(r *http.Request, OAuthSpec *UpstreamOAuth, err error) (string, error) {
	OAuthSpec.emitUpstreamOAuthEvent(r, UpstreamOAuthErrorEventName, err.Error(), OAuthSpec.Spec.APIID)
	return "", err
}

func (p *ClientCredentialsOAuthProvider) getOAuthToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	if OAuthSpec.Gw.UpstreamOAuthCache == nil {
		OAuthSpec.Gw.UpstreamOAuthCache = newUpstreamOAuthClientCredentialsCache(OAuthSpec.Gw.StorageConnectionHandler)
	}

	token, err := OAuthSpec.Gw.UpstreamOAuthCache.getToken(r, OAuthSpec)
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func generateCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	key := fmt.Sprintf(
		"%s|%s|%s|%s",
		apiId,
		config.ClientCredentials.ClientID,
		config.ClientCredentials.TokenURL,
		strings.Join(config.ClientCredentials.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

func (cache *upstreamOAuthClientCredentialsCache) getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	cacheKey := generateCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	tokenString, err := retryGetKeyAndLock(cacheKey, &cache.RedisCluster)
	if err != nil {
		return "", err
	}

	if tokenString != "" {
		decryptedToken := decrypt(getPaddedSecret(OAuthSpec.Gw), tokenString)
		return decryptedToken, nil
	}

	token, err := cache.obtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := encrypt(getPaddedSecret(OAuthSpec.Gw), token.AccessToken)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cacheKey, encryptedToken, ttl, &cache.RedisCluster); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func retryGetKeyAndLock(cacheKey string, cache *storage.RedisCluster) (string, error) {
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	var token string
	var err error

	for i := 0; i < maxRetries; i++ {
		token, err = cache.GetKey(cacheKey)
		if err == nil {
			return token, nil
		}

		lockKey := cacheKey + ":lock"
		ok, err := cache.Lock(lockKey, time.Second*5)
		if err == nil && ok {
			return "", nil
		}

		time.Sleep(retryDelay)
	}

	return "", fmt.Errorf("failed to acquire lock after retries: %v", err)
}

func newOAuth2ClientCredentialsConfig(OAuthSpec *UpstreamOAuth) oauth2clientcredentials.Config {
	return oauth2clientcredentials.Config{
		ClientID:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientID,
		ClientSecret: OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientSecret,
		TokenURL:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.TokenURL,
		Scopes:       OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Scopes,
	}
}

func (cache *upstreamOAuthClientCredentialsCache) obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)

	tokenSource := cfg.TokenSource(ctx)
	oauthToken, err := tokenSource.Token()
	if err != nil {
		return &oauth2.Token{}, err
	}

	return oauthToken, nil
}

func setTokenInCache(cacheKey string, token string, ttl time.Duration, cache *storage.RedisCluster) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(oauthTokenExpiry.Sub(time.Now()).Seconds()))
}

// UpstreamOAuthProvider implements upstream auth provider.
type UpstreamOAuthProvider struct {
	// HeaderName is the header name to be used to fill upstream auth with.
	HeaderName string
	// AuthValue is the value of auth header.
	AuthValue string
}

// Fill sets the request's HeaderName with AuthValue
func (u UpstreamOAuthProvider) Fill(r *http.Request) {
	if r.Header.Get(u.HeaderName) != "" {
		log.WithFields(logrus.Fields{
			"header": u.HeaderName,
		}).Info("Authorization header conflict detected: Client header overwritten by Gateway upstream authentication header.")
	}
	r.Header.Set(u.HeaderName, u.AuthValue)
}
