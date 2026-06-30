package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TykTechnologies/storage/temporal/model"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage/iamauth/gcp"
)

// buildIAMAuthOption returns a storage Option that wires an IAM-based credentials
// provider, or nil when IAM auth is disabled. It returns an error for an
// unsupported provider or an invalid configuration value.
func buildIAMAuthOption(ctx context.Context, cfg config.IAMAuthConfig) (model.Option, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "gcp":
		refresh, err := parseRefreshBeforeExpiry(cfg.TokenRefreshBeforeExpiry)
		if err != nil {
			return nil, err
		}

		provider, err := gcp.NewCredentialsProvider(ctx, gcp.Config{
			ServiceAccount:      cfg.ServiceAccount,
			RefreshBeforeExpiry: refresh,
		})
		if err != nil {
			return nil, err
		}

		return model.WithCredentialsProvider(provider), nil
	default:
		return nil, fmt.Errorf("unsupported iam_auth provider %q (supported: \"gcp\")", cfg.Provider)
	}
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
