package gcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type fakeTokenSource struct {
	tok *oauth2.Token
	err error
}

func (f fakeTokenSource) Token() (*oauth2.Token, error) { return f.tok, f.err }

func TestProviderFromTokenSource_ReturnsDefaultUserAndToken(t *testing.T) {
	ts := fakeTokenSource{tok: &oauth2.Token{AccessToken: "iam-token-abc"}}
	provider := providerFromTokenSource(ts)

	user, pass, err := provider(context.Background())
	require.NoError(t, err)
	// GCP Memorystore (Valkey and Redis Cluster) expect the "default" ACL user
	// with the OAuth2 access token supplied as the password.
	assert.Equal(t, "default", user)
	assert.Equal(t, "iam-token-abc", pass)
}

func TestProviderFromTokenSource_PropagatesError(t *testing.T) {
	ts := fakeTokenSource{err: errors.New("adc unavailable")}
	provider := providerFromTokenSource(ts)

	_, _, err := provider(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "adc unavailable")
}
