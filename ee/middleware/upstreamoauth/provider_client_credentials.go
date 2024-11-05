package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func (cache *ClientCredentialsClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(cache.mw)
	tokenSource := cfg.TokenSource(ctx)
	return tokenSource.Token()
}

func (cache *ClientCredentialsClient) GetToken(r *http.Request) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(cache.mw.Spec.UpstreamAuth.OAuth, cache.mw.Spec.APIID)
	secret := cache.mw.Gw.GetConfig().Secret
	extraMetadata := cache.mw.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return cache.ObtainToken(ctx)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, cache.mw.clientCredentialsStorageHandler)
}
