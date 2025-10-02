package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func (client *PasswordClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2PasswordConfig(client.mw)

	// Use external services HTTP client if configured
	if httpClient := client.getHTTPClient(); httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	return cfg.PasswordCredentialsToken(ctx, client.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Username, client.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Password)
}

func (client *PasswordClient) GetToken(r *http.Request) (string, error) {
	cacheKey := generatePasswordOAuthCacheKey(client.mw.Spec.UpstreamAuth.OAuth, client.mw.Spec.APIID)
	secret := client.mw.Gw.GetConfig().Secret
	extraMetadata := client.mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return client.ObtainToken(ctx)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, client.mw.passwordStorageHandler)
}

// getHTTPClient creates an HTTP client with external services configuration if available
func (client *PasswordClient) getHTTPClient() *http.Client {
	return createOAuthHTTPClient(client.mw)
}
