package rate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/storage/temporal/model"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// applyIAMAuth must attach the credentials provider and clear any static
// username/password, so short-lived IAM tokens become the only credential
// source for the rate limiter's Redis connection.
func TestApplyIAMAuth_SetsProviderAndClearsStaticCreds(t *testing.T) {
	opts := &redis.UniversalOptions{Username: "static-user", Password: "static-pass"}

	var provider model.CredentialsProviderFunc = func(context.Context) (string, string, error) {
		return "default", "token", nil
	}

	applyIAMAuth(opts, provider)

	require.NotNil(t, opts.CredentialsProviderContext, "provider must be wired onto the options")
	assert.Empty(t, opts.Username, "static username must be cleared under IAM auth")
	assert.Empty(t, opts.Password, "static password must be cleared under IAM auth")

	user, pass, err := opts.CredentialsProviderContext(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "default", user)
	assert.Equal(t, "token", pass)
}

// With IAM auth disabled, options must retain their static credentials and
// carry no credentials provider.
func TestBuildUniversalOptions_IAMDisabled_KeepsStaticCreds(t *testing.T) {
	cfg := &config.StorageOptionsConf{Username: "static-user", Password: "static-pass"}

	opts, err := buildUniversalOptions(cfg, nil)

	require.NoError(t, err)
	assert.Nil(t, opts.CredentialsProviderContext)
	assert.Equal(t, "static-user", opts.Username)
	assert.Equal(t, "static-pass", opts.Password)
}

// An unsupported provider must be rejected (routed through the shared iamauth
// selector), naming the offending provider.
func TestBuildIAMProvider_UnsupportedProvider_Errors(t *testing.T) {
	_, err := buildIAMProvider(config.IAMAuthConfig{Enabled: true, Provider: "azure"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure")
}

// An invalid refresh duration must be rejected before any provider setup.
func TestBuildIAMProvider_InvalidRefresh_Errors(t *testing.T) {
	_, err := buildIAMProvider(config.IAMAuthConfig{
		Enabled:                  true,
		Provider:                 "gcp",
		TokenRefreshBeforeExpiry: "notaduration",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_refresh_before_expiry")
}

// NewStorage must surface an error (and return no client) when the IAM provider
// cannot be constructed, rather than silently handing back a client that will
// fail AUTH against an IAM-only Redis.
func TestNewStorage_IAMProviderError_ReturnsError(t *testing.T) {
	cfg := &config.StorageOptionsConf{
		IAMAuth: config.IAMAuthConfig{Enabled: true, Provider: "azure"},
	}

	client, err := NewStorage(cfg, nil)

	require.Error(t, err)
	assert.Nil(t, client)
}
