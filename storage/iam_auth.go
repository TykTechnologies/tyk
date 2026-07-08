package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TykTechnologies/storage/iamauth"
	"github.com/TykTechnologies/storage/temporal/model"

	"github.com/TykTechnologies/tyk/config"
)

// buildIAMAuthOption returns a storage Option that wires an IAM-based credentials
// provider, or nil when IAM auth is disabled. It returns an error for an
// unsupported provider or an invalid configuration value.
//
// Provider selection and the cloud SDKs live in the storage library's iamauth
// package; this adapter only maps Gateway config onto iamauth.Config.
func buildIAMAuthOption(ctx context.Context, cfg config.IAMAuthConfig) (model.Option, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	refresh, err := parseRefreshBeforeExpiry(cfg.TokenRefreshBeforeExpiry)
	if err != nil {
		return nil, err
	}

	provider, err := iamauth.NewProvider(ctx, iamauth.Config{
		Provider:            strings.ToLower(strings.TrimSpace(cfg.Provider)),
		ServiceAccount:      cfg.ServiceAccount,
		RefreshBeforeExpiry: refresh,
	})
	if err != nil {
		return nil, err
	}

	return model.WithCredentialsProvider(provider), nil
}

// parseRefreshBeforeExpiry parses the optional refresh duration. An empty value
// yields a zero duration, letting the provider apply its own default.
func parseRefreshBeforeExpiry(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid token_refresh_before_expiry %q: %w", raw, err)
	}
	return d, nil
}
