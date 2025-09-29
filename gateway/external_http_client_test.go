package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestExternalHTTPClientFactory_NewExternalHTTPClientFactory(t *testing.T) {
	// Test that the gateway wrapper creates the factory correctly
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Global: config.GlobalProxyConfig{
				Enabled: true,
			},
		},
	}

	// Use the test helper to create a properly initialized Gateway
	ts := StartTest(func(globalConf *config.Config) {
		*globalConf = gwConfig
	})
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)
	require.NotNil(t, factory)

	// The factory should be created but we delegate to internal/httpclient for the actual implementation
	assert.NotNil(t, factory.factory)
}

func TestExternalHTTPClientFactory_CreateClient_Integration(t *testing.T) {
	// Test the gateway integration with the underlying factory
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Global: config.GlobalProxyConfig{
				Enabled:   true,
				HTTPProxy: "http://proxy:8080",
			},
		},
	}

	ts := StartTest(func(globalConf *config.Config) {
		*globalConf = gwConfig
	})
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test OAuth client creation
	client, err := factory.CreateClient(config.ServiceTypeOAuth)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.IsType(t, &http.Client{}, client)
}

func TestExternalHTTPClientFactory_SpecializedClients(t *testing.T) {
	// Test the specialized client creation methods
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Global: config.GlobalProxyConfig{
				Enabled: true,
			},
		},
	}

	ts := StartTest(func(globalConf *config.Config) {
		*globalConf = gwConfig
	})
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)

	t.Run("CreateJWKClient", func(t *testing.T) {
		client, err := factory.CreateJWKClient()
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("CreateIntrospectionClient", func(t *testing.T) {
		client, err := factory.CreateIntrospectionClient()
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("CreateWebhookClient", func(t *testing.T) {
		client, err := factory.CreateWebhookClient()
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("CreateHealthCheckClient", func(t *testing.T) {
		client, err := factory.CreateHealthCheckClient()
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestExternalHTTPClientFactory_NoConfiguration(t *testing.T) {
	// Test that without configuration, clients can't be created
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			// No configuration
		},
	}

	ts := StartTest(func(globalConf *config.Config) {
		*globalConf = gwConfig
	})
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)

	client, err := factory.CreateClient(config.ServiceTypeOAuth)
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), "external services not configured")
}
