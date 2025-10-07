package upstreamoauth

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// loggingRoundTripper wraps a RoundTripper to log TLS certificate usage
type loggingRoundTripper struct {
	base   http.RoundTripper
	logger func(format string, args ...interface{})
}

func (l *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log the request
	l.logger("[UpstreamOAuth] Making request to: %s %s", req.Method, req.URL.String())

	// Log request headers
	l.logger("[UpstreamOAuth] Request headers:")
	for name, values := range req.Header {
		for _, value := range values {
			// Mask sensitive values
			displayValue := value
			if name == "Authorization" && len(value) > 20 {
				displayValue = value[:20] + "..."
			}
			l.logger("[UpstreamOAuth]   %s: %s", name, displayValue)
		}
	}

	// Log request body for POST requests
	if req.Method == "POST" && req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		l.logger("[UpstreamOAuth] Request body: %s", string(bodyBytes))
	}

	// Check if we have TLS config
	if transport, ok := l.base.(*http.Transport); ok {
		if transport.TLSClientConfig != nil {
			l.logger("[UpstreamOAuth] RoundTrip - TLS config has %d certificates",
				len(transport.TLSClientConfig.Certificates))

			// Log certificate details
			for i, cert := range transport.TLSClientConfig.Certificates {
				l.logger("[UpstreamOAuth] Certificate[%d]: has %d certs in chain", i, len(cert.Certificate))
			}
		} else {
			l.logger("[UpstreamOAuth] RoundTrip - NO TLS config!")
		}
	}

	// Make the request
	resp, err := l.base.RoundTrip(req)
	if err != nil {
		l.logger("[UpstreamOAuth] Request failed: %v", err)
	} else {
		l.logger("[UpstreamOAuth] Request succeeded: %d", resp.StatusCode)

		// Log response body for errors
		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			l.logger("[UpstreamOAuth] Response body: %s", string(bodyBytes))
		}
	}

	return resp, err
}

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

		// Wrap the transport to log actual usage
		loggingClient := &http.Client{
			Transport: &loggingRoundTripper{
				base: httpClient.Transport,
				logger: func(format string, args ...interface{}) {
					client.mw.Logger().Debugf(format, args...)
				},
			},
			Timeout: httpClient.Timeout,
		}

		ctx = context.WithValue(ctx, oauth2.HTTPClient, loggingClient)
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
