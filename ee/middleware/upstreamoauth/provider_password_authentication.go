package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func (cache *PasswordClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2PasswordConfig(cache.mw)
	return cfg.PasswordCredentialsToken(ctx, cache.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Username, cache.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Password)
}

func (cache *PasswordClient) GetToken(r *http.Request) (string, error) {
	cacheKey := generatePasswordOAuthCacheKey(cache.mw.Spec.UpstreamAuth.OAuth, cache.mw.Spec.APIID)
	secret := cache.mw.Gw.GetConfig().Secret
	extraMetadata := cache.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return cache.ObtainToken(ctx)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, cache.mw.passwordStorageHandler)
}
