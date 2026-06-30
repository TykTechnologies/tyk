// Package gcp provides a credentials provider for authenticating to GCP
// Memorystore (Valkey and Redis Cluster) using IAM access tokens instead of a
// static Redis password.
//
// GCP Memorystore IAM auth works by sending the Redis/Valkey AUTH command with
// the "default" user and a short-lived Google OAuth2 access token as the
// password. Tokens last ~1 hour; existing connections survive token expiry and
// only new connections need a fresh token, so we simply hand out a currently
// valid token on each call. The same mechanism applies to both Memorystore for
// Valkey and Memorystore for Redis Cluster - only the IAM role granted on the
// GCP side differs, which is invisible to this client.
package gcp

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
)

// cloudPlatformScope is the OAuth2 scope required for Memorystore IAM auth.
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// defaultRefreshBeforeExpiry is how far ahead of a token's expiry we proactively
// refresh, so a brand-new connection never receives an almost-expired token.
const defaultRefreshBeforeExpiry = 5 * time.Minute

// Config configures the GCP IAM credentials provider.
type Config struct {
	// ServiceAccount, when set, is impersonated to mint tokens instead of using
	// the ambient Application Default Credentials identity. Optional.
	ServiceAccount string
	// RefreshBeforeExpiry is how far ahead of expiry tokens are refreshed.
	// Defaults to 5 minutes when zero.
	RefreshBeforeExpiry time.Duration
}

// NewCredentialsProvider builds a credentials provider that returns the
// "default" user and a fresh GCP IAM access token. The returned function is
// suitable for the storage library's WithCredentialsProvider option.
//
// Identity is resolved via Application Default Credentials (Workload Identity on
// GKE, GOOGLE_APPLICATION_CREDENTIALS elsewhere). If cfg.ServiceAccount is set,
// that account is impersonated instead.
func NewCredentialsProvider(ctx context.Context, cfg Config) (func(context.Context) (string, string, error), error) {
	refresh := cfg.RefreshBeforeExpiry
	if refresh <= 0 {
		refresh = defaultRefreshBeforeExpiry
	}

	base, err := baseTokenSource(ctx, cfg.ServiceAccount)
	if err != nil {
		return nil, err
	}

	// ReuseTokenSourceWithExpiry caches the token and refreshes it `refresh`
	// before its actual expiry, giving us proactive rotation for free.
	ts := oauth2.ReuseTokenSourceWithExpiry(nil, base, refresh)

	return providerFromTokenSource(ts), nil
}

// baseTokenSource returns the underlying OAuth2 token source: either ambient ADC
// or an impersonated service account.
func baseTokenSource(ctx context.Context, serviceAccount string) (oauth2.TokenSource, error) {
	if serviceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: serviceAccount,
			Scopes:          []string{cloudPlatformScope},
		})
		if err != nil {
			return nil, fmt.Errorf("gcp iam: configuring impersonation for %q: %w", serviceAccount, err)
		}
		return ts, nil
	}

	ts, err := google.DefaultTokenSource(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("gcp iam: resolving application default credentials: %w", err)
	}
	return ts, nil
}

// providerFromTokenSource adapts an OAuth2 token source into the credentials
// provider signature expected by the storage library.
func providerFromTokenSource(ts oauth2.TokenSource) func(context.Context) (string, string, error) {
	return func(_ context.Context) (string, string, error) {
		tok, err := ts.Token()
		if err != nil {
			return "", "", fmt.Errorf("gcp iam: fetching access token: %w", err)
		}
		return "default", tok.AccessToken, nil
	}
}
