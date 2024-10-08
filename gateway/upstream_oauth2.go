package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
	"golang.org/x/oauth2"
	oauth2clientcredentials "golang.org/x/oauth2/clientcredentials"
	"net/http"
	"strings"
	"time"
)

var (
	oAuthUpstreamCache  *upstreamOauthCache
	oAuthTokenProviders = make(map[string]oauth2.TokenSource)
)

type oAuthHeaderProvider interface {
	getOAuthHeaderValue(r *http.Request, spec *APISpec, gateway *Gateway) (string, error)
	invalidateTokenCache(spec *APISpec)
}

type distributedCacheOAuthProvider struct{}

func (p *distributedCacheOAuthProvider) invalidateTokenCache(spec *APISpec) {
	cacheKey := generateCacheKey(spec.UpstreamAuth.OAuth, spec.APIID)
	oAuthUpstreamCache.DeleteKey(cacheKey)
}

type perAPIOAuthProvider struct{}

func (p *perAPIOAuthProvider) invalidateTokenCache(spec *APISpec) {
	cacheKey := generateCacheKey(spec.UpstreamAuth.OAuth, spec.APIID)
	delete(oAuthTokenProviders, cacheKey)
}

type upstreamOAuthHeader struct {
	name  string
	value string
}

func InvalidateUpstreamOAuthCache(spec *APISpec) {
	provider := getOAuthHeaderProvider(spec.UpstreamAuth.OAuth)
	provider.invalidateTokenCache(spec)
}

// ProcessRequest will inject basic auth info into request context so that it can be used during reverse proxy.
func getUpstreamOAuth(r *http.Request, spec *APISpec, gateway *Gateway) (upstreamOAuthHeader, error) {
	oauthConfig := spec.UpstreamAuth.OAuth

	var upstreamOAuthHeaderValue upstreamOAuthHeader
	upstreamOAuthHeaderValue.name = header.Authorization
	if oauthConfig.HeaderName != "" {
		upstreamOAuthHeaderValue.name = oauthConfig.HeaderName
	}

	var err error
	provider := getOAuthHeaderProvider(oauthConfig)
	upstreamOAuthHeaderValue.value, err = provider.getOAuthHeaderValue(r, spec, gateway)
	if err != nil {
		return upstreamOAuthHeader{}, fmt.Errorf("failed to get OAuth token: %v", err)
	}

	return upstreamOAuthHeaderValue, nil
}

func getOAuthHeaderProvider(oauthConfig apidef.UpstreamOAuth) oAuthHeaderProvider {
	if oauthConfig.DistributedToken {
		return &distributedCacheOAuthProvider{}
	}
	return &perAPIOAuthProvider{}
}

func (p *perAPIOAuthProvider) getOAuthHeaderValue(r *http.Request, spec *APISpec, gateway *Gateway) (string, error) {
	oauthConfig := spec.UpstreamAuth.OAuth

	mapHash := generateCacheKey(oauthConfig, spec.APIID)
	if _, ok := oAuthTokenProviders[mapHash]; !ok {
		cfg := newOAuth2ClientCredentialsConfig(spec)
		oAuthTokenProviders[mapHash] = cfg.TokenSource(context.Background())
	}

	provider, ok := oAuthTokenProviders[mapHash]
	if !ok {
		return "", fmt.Errorf("failed to get OAuth token provider")
	}

	oauthToken, err := provider.Token()
	if err != nil {
		spec.emitUpstreamOAuthEvent(r, "UpstreamOAuthError", err.Error(), "obtainToken")
		return "", err
	}

	payload := fmt.Sprintf("Bearer %s", oauthToken.AccessToken)
	return payload, nil
}

func (p *distributedCacheOAuthProvider) getOAuthHeaderValue(r *http.Request, spec *APISpec, gateway *Gateway) (string, error) {
	if oAuthUpstreamCache == nil {
		oAuthUpstreamCache = newUpstreamOauthCache(gateway)
	}

	token, err := oAuthUpstreamCache.getToken(r, spec)
	if err != nil {
		return "", err
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

func (cache *upstreamOauthCache) getToken(r *http.Request, spec *APISpec) (string, error) {
	cacheKey := generateCacheKey(spec.UpstreamAuth.OAuth, spec.APIID)

	token, err := cache.retryGetKeyAndLock(cacheKey)
	if err != nil {
		spec.emitUpstreamOAuthEvent(r, "UpstreamOAuthError", err.Error(), "obtainToken")
		return "", err
	}

	if token != "" {
		decryptedToken := decrypt(getPaddedSecret(spec.GlobalConfig.Secret), token)
		return decryptedToken, nil
	}

	token, err = cache.obtainToken(context.Background(), spec)
	if err != nil {
		spec.emitUpstreamOAuthEvent(r, "UpstreamOAuthError", err.Error(), "obtainNewToken")
		return "", err
	}

	encryptedToken := encrypt(getPaddedSecret(spec.GlobalConfig.Secret), token)

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

func newOAuth2ClientCredentialsConfig(spec *APISpec) oauth2clientcredentials.Config {
	return oauth2clientcredentials.Config{
		ClientID:       spec.UpstreamAuth.OAuth.ClientCredentials.ClientID,
		ClientSecret:   spec.UpstreamAuth.OAuth.ClientCredentials.ClientSecret,
		TokenURL:       spec.UpstreamAuth.OAuth.ClientCredentials.TokenURL,
		Scopes:         spec.UpstreamAuth.OAuth.ClientCredentials.Scopes,
		EndpointParams: spec.UpstreamAuth.OAuth.ClientCredentials.EndpointParams,
		AuthStyle:      oauth2.AuthStyle(spec.UpstreamAuth.OAuth.ClientCredentials.AuthStyle),
	}
}

func (cache *upstreamOauthCache) obtainToken(ctx context.Context, spec *APISpec) (string, error) {
	cfg := newOAuth2ClientCredentialsConfig(spec)

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
