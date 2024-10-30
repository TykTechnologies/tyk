package upstreamoauth

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/internal/crypto"
)

type Cache interface {
	// GetToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	GetToken(r *http.Request, OAuthSpec *Middleware) (string, error)
	// ObtainToken issues a request to obtain the token from the OAuth provider.
	ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error)
}

func getToken(r *http.Request, cacheKey string, obtainTokenFunc func(context.Context) (*oauth2.Token, error), secret string, extraMetadata []string, cache Storage) (string, error) {
	tokenString, err := retryGetKeyAndLock(cacheKey, cache)
	if err != nil {
		return "", err
	}

	if tokenString != "" {
		decryptedToken := crypto.Decrypt(crypto.GetPaddedString(secret), tokenString)
		return decryptedToken, nil
	}

	token, err := obtainTokenFunc(r.Context())
	if err != nil {
		return "", err
	}

	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(secret), token.AccessToken)
	setExtraMetadata(r, extraMetadata, token)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cache, cacheKey, encryptedToken, ttl); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func (cache *PasswordClient) GetToken(r *http.Request, mw *Middleware) (string, error) {
	cacheKey := generatePasswordOAuthCacheKey(mw.Spec.UpstreamAuth.OAuth, mw.Spec.APIID)
	secret := mw.Gw.GetConfig().Secret
	extraMetadata := mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return cache.ObtainToken(ctx, mw)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, cache.Storage)
}

func (cache *ClientCredentialsClient) GetToken(r *http.Request, OAuthSpec *Middleware) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)
	secret := OAuthSpec.Gw.GetConfig().Secret
	extraMetadata := OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return cache.ObtainToken(ctx, OAuthSpec)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, cache.Storage)
}

func setTokenInCache(cache Storage, cacheKey string, token string, ttl time.Duration) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(time.Until(oauthTokenExpiry).Seconds()))
}

func (cache *ClientCredentialsClient) ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)

	tokenSource := cfg.TokenSource(ctx)
	oauthToken, err := tokenSource.Token()
	if err != nil {
		return &oauth2.Token{}, err
	}

	return oauthToken, nil
}

func (cache *PasswordClient) ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error) {
	cfg := newOAuth2PasswordConfig(OAuthSpec)

	token, err := cfg.PasswordCredentialsToken(ctx, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Username, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Password)
	if err != nil {
		return &oauth2.Token{}, err
	}

	return token, nil
}
