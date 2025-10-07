package upstreamoauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func (client *ClientCredentialsClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(client.mw)

	// Use external services HTTP client if configured
	if httpClient := client.getHTTPClient(); httpClient != nil {
		client.mw.Logger().Debugf("[UpstreamOAuth] Setting custom HTTP client in context - Transport type: %T", httpClient.Transport)
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig != nil {
				client.mw.Logger().Debugf("[UpstreamOAuth] TLS config present - Certificates: %d, InsecureSkipVerify: %v",
					len(transport.TLSClientConfig.Certificates), transport.TLSClientConfig.InsecureSkipVerify)
			} else {
				client.mw.Logger().Warn("[UpstreamOAuth] TLS config is nil!")
			}
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	} else {
		client.mw.Logger().Warn("[UpstreamOAuth] No custom HTTP client configured, oauth2 will use default client")
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
	return createOAuthHTTPClient(client.mw)
}
