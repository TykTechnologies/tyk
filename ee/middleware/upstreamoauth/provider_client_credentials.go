package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/internal/httpclient"
)

func (client *ClientCredentialsClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(client.mw)

	// Use external services HTTP client if configured
	if httpClient := client.getHTTPClient(); httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	tokenSource := cfg.TokenSource(ctx)
	return tokenSource.Token()
}

func (client *ClientCredentialsClient) GetToken(r *http.Request) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(client.mw.Spec.UpstreamAuth.OAuth, client.mw.Spec.APIID)
	secret := client.mw.Gw.GetConfig().Secret
	extraMetadata := client.mw.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata

	obtainTokenFunc := func(ctx context.Context) (*oauth2.Token, error) {
		return client.ObtainToken(ctx)
	}

	return getToken(r, cacheKey, obtainTokenFunc, secret, extraMetadata, client.mw.clientCredentialsStorageHandler)
}

// getHTTPClient creates an HTTP client with external services configuration if available
func (client *ClientCredentialsClient) getHTTPClient() *http.Client {
	gwConfig := client.mw.Gw.GetConfig()
	if gwConfig.ExternalServices.OAuth.MTLS.Enabled ||
		gwConfig.ExternalServices.OAuth.Proxy.Enabled ||
		gwConfig.ExternalServices.Global.Enabled {

		// Create HTTP httpClient factory
		factory := httpclient.NewExternalHTTPClientFactory(&gwConfig.ExternalServices, client.mw.Gw.GetCertificateManager())

		// Try to create OAuth httpClient with proper error handling
		httpClient, err := factory.CreateOAuthClient()
		if err != nil {
			// Log the configuration error but continue with default httpClient
			if client.mw != nil && client.mw.Base != nil {
				client.mw.Logger().WithError(err).Warn("Failed to create custom HTTP httpClient for upstream OAuth, falling back to default httpClient. Check external services configuration.")
			}
			return nil
		}

		if client.mw != nil && client.mw.Base != nil {
			client.mw.Logger().Debug("Successfully created custom HTTP httpClient for upstream OAuth with external services configuration")
		}
		return httpClient
	}

	// Return nil to use default HTTP client
	return nil
}
