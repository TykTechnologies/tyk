package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/internal/httpclient"
)

func (cache *ClientCredentialsClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(cache.mw)

	// Use external services HTTP client if configured
	if httpClient := cache.getHTTPClient(); httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

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

// getHTTPClient creates an HTTP client with external services configuration if available
func (cache *ClientCredentialsClient) getHTTPClient() *http.Client {
	gwConfig := cache.mw.Gw.GetConfig()
	if gwConfig.ExternalServices.OAuth.MTLS.Enabled ||
		gwConfig.ExternalServices.OAuth.Proxy.Enabled ||
		gwConfig.ExternalServices.Global.Enabled {

		// Create HTTP client factory
		factory := httpclient.NewExternalHTTPClientFactory(&gwConfig.ExternalServices, cache.mw.Gw.GetCertificateManager())

		// Try to create OAuth client
		if client, err := factory.CreateOAuthClient(); err == nil {
			return client
		}
	}

	// Return nil to use default HTTP client
	return nil
}
