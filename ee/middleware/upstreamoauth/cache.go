package upstreamoauth

import (
	"context"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/internal/crypto"
	"golang.org/x/oauth2"
)

type Cache interface {
	// GetToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	GetToken(r *http.Request, OAuthSpec *Middleware) (string, error)
	// ObtainToken issues a request to obtain the token from the OAuth provider.
	ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error)
}

func (cache *ClientCredentialsClient) GetToken(r *http.Request, OAuthSpec *Middleware) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	tokenString, err := retryGetKeyAndLock(cacheKey, cache.Storage)
	if err != nil {
		return "", err
	}

	if tokenString != "" {
		decryptedToken := crypto.Decrypt(crypto.GetPaddedString(OAuthSpec.Gw.GetConfig().Secret), tokenString)
		return decryptedToken, nil
	}

	token, err := cache.ObtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(OAuthSpec.Gw.GetConfig().Secret), token.AccessToken)
	setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata, token)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cache.Storage, cacheKey, encryptedToken, ttl); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func setTokenInCache(cache Storage, cacheKey string, token string, ttl time.Duration) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(oauthTokenExpiry.Sub(time.Now()).Seconds()))
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
