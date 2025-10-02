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
			// If mTLS is explicitly enabled and the error is related to certificate loading,
			// we should not fallback to default client as this would bypass required mutual TLS authentication
			if gwConfig.ExternalServices.OAuth.MTLS.Enabled && httpclient.IsMTLSError(err) {
				if client.mw != nil && client.mw.Base != nil {
					client.mw.Logger().WithError(err).Error("mTLS configuration failed for upstream OAuth. This is a security-critical error - requests cannot proceed without proper mutual TLS authentication.")
				}
				// Don't return a client at all - let the OAuth flow fail properly
				return nil
			}
			// For other errors (e.g., not configured, proxy config), log warning and fallback
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
