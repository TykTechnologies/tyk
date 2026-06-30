package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestBuildIAMAuthOption_Disabled(t *testing.T) {
	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, opt, "no option should be returned when IAM auth is disabled")
}

func TestBuildIAMAuthOption_UnsupportedProvider(t *testing.T) {
	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{
		Enabled:  true,
		Provider: "aws",
	})
	require.Error(t, err)
	assert.Nil(t, opt)
	assert.Contains(t, err.Error(), "aws")
}

func TestBuildIAMAuthOption_EmptyProvider(t *testing.T) {
	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{Enabled: true})
	require.Error(t, err)
	assert.Nil(t, opt)
}

func TestBuildIAMAuthOption_InvalidRefreshDuration(t *testing.T) {
	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{
		Enabled:                  true,
		Provider:                 "gcp",
		TokenRefreshBeforeExpiry: "not-a-duration",
	})
	require.Error(t, err)
	assert.Nil(t, opt)
	assert.Contains(t, err.Error(), "token_refresh_before_expiry")
}
