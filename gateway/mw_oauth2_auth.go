package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
	"golang.org/x/oauth2"
	oauth2clientcredentials "golang.org/x/oauth2/clientcredentials"
	"net/http"
	"strings"
	"time"
)

var (
	oAuthUpstreamCache *upstreamOauthCache
)

type OAuthHeaderProvider interface {
	getOAuthHeaderValue(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error)
}

type DistributedCacheOAuthProvider struct{}

type PerAPIOAuthProvider struct{}

// UpstreamOAuth is a middleware that will do basic authentication for upstream connections.
// UpstreamOAuth middleware is only supported in Tyk OAS API definitions.
type UpstreamOAuth struct {
	*BaseMiddleware
}

// Name returns the name of middleware.
func (OAuthSpec *UpstreamOAuth) Name() string {
	return "UpstreamOAuth"
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

	authHeaderName := header.Authorization
	if oauthConfig.HeaderName != "" {
		authHeaderName = oauthConfig.HeaderName
	}
	ctx.SetUpstreamAuthHeader(r, authHeaderName)

	provider := getOAuthHeaderProvider(oauthConfig)

	payload, err := provider.getOAuthHeaderValue(r, OAuthSpec)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %v", err), http.StatusInternalServerError
	}

	ctx.SetUpstreamAuthValue(r, payload)
	return nil, http.StatusOK
}

func getOAuthHeaderProvider(oauthConfig apidef.UpstreamOAuth) OAuthHeaderProvider {
	if oauthConfig.DistributedToken {
		return &DistributedCacheOAuthProvider{}
	}
	return &PerAPIOAuthProvider{}
}

func (p *PerAPIOAuthProvider) getOAuthHeaderValue(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	oauthConfig := OAuthSpec.Spec.UpstreamAuth.OAuth

	if oauthConfig.ClientCredentials.TokenProvider == nil || ctx.ShouldRefreshUpstreamOAuthToken(r) {
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
	phase := determinePhase(r)
	OAuthSpec.emitUpstreamOAuthEvent(r, "UpstreamOAuthError", err.Error(), OAuthSpec.Spec.APIID, phase)
	return "", err
}

func determinePhase(r *http.Request) string {
	if ctx.ShouldRefreshUpstreamOAuthToken(r) {
		return "refresh"
	}
	return "initial"
}

func (p *DistributedCacheOAuthProvider) getOAuthHeaderValue(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	if oAuthUpstreamCache == nil {
		oAuthUpstreamCache = newUpstreamOauthCache(OAuthSpec.Gw)
	}

	token, err := oAuthUpstreamCache.getToken(r, OAuthSpec)
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	payload := fmt.Sprintf("Bearer %s", token)
	return payload, nil
}

func newUpstreamOauthCache(gw *Gateway) *upstreamOauthCache {
	return &upstreamOauthCache{RedisCluster: storage.RedisCluster{KeyPrefix: "upstreamOAuth-", ConnectionHandler: gw.StorageConnectionHandler}}
}

type upstreamOauthCache struct {
	storage.RedisCluster
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

func (cache *upstreamOauthCache) getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	cacheKey := generateCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	if ctx.ShouldRefreshUpstreamOAuthToken(r) {
		if deleted := cache.DeleteKey(cacheKey); deleted != false {
			return "", errors.New("failed to delete token from cache")
		}
	}

	token, err := cache.retryGetKeyAndLock(cacheKey)
	if err != nil {
		return "", err
	}

	if token != "" {
		decryptedToken := decrypt(getPaddedSecret(OAuthSpec.Gw), token)
		return decryptedToken, nil
	}

	token, err = cache.obtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := encrypt(getPaddedSecret(OAuthSpec.Gw), token)

	if err := cache.setTokenInCache(cacheKey, encryptedToken); err != nil {
		return "", err
	}

	return token, nil
}

func (cache *upstreamOauthCache) retryGetKeyAndLock(cacheKey string) (string, error) {
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
		ClientID:       OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientID,
		ClientSecret:   OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientSecret,
		TokenURL:       OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.TokenURL,
		Scopes:         OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Scopes,
		EndpointParams: OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.EndpointParams,
		AuthStyle:      oauth2.AuthStyle(OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.AuthStyle),
	}
}

func (cache *upstreamOauthCache) obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (string, error) {
	cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)

	tokenSource := cfg.TokenSource(ctx)
	oauthToken, err := tokenSource.Token()
	if err != nil {
		return "", err
	}

	return oauthToken.AccessToken, nil
}

func (cache *upstreamOauthCache) setTokenInCache(cacheKey, token string) error {
	oauthTokenExpiry := time.Now().Add(time.Hour)
	return cache.SetKey(cacheKey, token, int64(oauthTokenExpiry.Sub(time.Now()).Seconds()))
}
