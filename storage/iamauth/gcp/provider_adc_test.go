package gcp

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCredentialsProvider_ADC_Integration mints a real Google OAuth2 access
// token through Application Default Credentials and verifies the provider
// returns the "default" user with a non-empty token. It proves the ADC/token
// path actually works against Google, short of a real Memorystore instance.
//
// Set up ADC first, then run:
//
//	gcloud auth application-default login
//	RUN_GCP_ADC_TEST=1 go test ./storage/iamauth/gcp/ \
//	  -run TestNewCredentialsProvider_ADC_Integration -v
func TestNewCredentialsProvider_ADC_Integration(t *testing.T) {
	if os.Getenv("RUN_GCP_ADC_TEST") == "" {
		t.Skip("set RUN_GCP_ADC_TEST=1 (with ADC configured) to run the live GCP token test")
	}

	ctx := context.Background()
	provider, err := NewCredentialsProvider(ctx, Config{})
	require.NoError(t, err, "ADC must be configured (gcloud auth application-default login)")

	user, token, err := provider(ctx)
	require.NoError(t, err, "should mint a real Google access token")
	assert.Equal(t, "default", user)
	assert.NotEmpty(t, token, "expected a non-empty OAuth2 access token")
	// Google access tokens are opaque but conventionally start with "ya29.".
	assert.Greater(t, len(token), 20, "token looks too short to be a real access token")
	t.Logf("minted access token of length %d", len(token))
}
