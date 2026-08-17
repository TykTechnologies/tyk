package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/iamtest"
)

func TestBuildIAMAuthOption_Disabled(t *testing.T) {
	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, opt, "no option should be returned when IAM auth is disabled")
}

func TestBuildIAMAuthOption_Success(t *testing.T) {
	// Hermetic ADC lets the gcp provider resolve credentials and mint its
	// initial token offline, so the success path returns a usable option.
	iamtest.FakeADC(t)

	opt, err := buildIAMAuthOption(context.Background(), config.IAMAuthConfig{
		Enabled:  true,
		Provider: "gcp",
	})
	require.NoError(t, err)
	assert.NotNil(t, opt, "a credentials-provider option must be returned when IAM auth is configured")
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
	// The refresh duration is now parsed inside the storage iamauth package;
	// the error names the offending value.
	assert.Contains(t, err.Error(), "not-a-duration")
}
