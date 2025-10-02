package upstreamoauth

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpclient"
)

// createOAuthHTTPClient creates an HTTP client for OAuth operations with proper mTLS error handling
func createOAuthHTTPClient(mw *Middleware) *http.Client {
	gwConfig := mw.Gw.GetConfig()

	// Check if external services are configured
	if !gwConfig.ExternalServices.OAuth.MTLS.Enabled &&
		!gwConfig.ExternalServices.OAuth.Proxy.Enabled &&
		!gwConfig.ExternalServices.Global.Enabled {
		return nil
	}

	// Create HTTP client factory
	factory := httpclient.NewExternalHTTPClientFactory(&gwConfig.ExternalServices, mw.Gw.GetCertificateManager())

	// Try to create OAuth client with proper error handling
	httpClient, err := factory.CreateOAuthClient()
	if err != nil {
		// If mTLS is explicitly enabled and the error is related to certificate loading,
		// we should not fallback to default client as this would bypass required mutual TLS authentication
		if gwConfig.ExternalServices.OAuth.MTLS.Enabled && httpclient.IsMTLSError(err) {
			if mw != nil && mw.Base != nil {
				mw.Logger().WithError(err).Error("mTLS configuration failed for upstream OAuth. This is a security-critical error - requests cannot proceed without proper mutual TLS authentication.")
			}
			// Don't return a client at all - let the OAuth flow fail properly
			return nil
		}
		// For other errors (e.g., not configured, proxy config), log warning and fallback
		if mw != nil && mw.Base != nil {
			mw.Logger().WithError(err).Warn("Failed to create custom HTTP httpClient for upstream OAuth, falling back to default httpClient. Check external services configuration.")
		}
		return nil
	}

	if mw != nil && mw.Base != nil {
		mw.Logger().Debug("[ExternalServices] Using external services OAuth client")
	}
	return httpClient
}
