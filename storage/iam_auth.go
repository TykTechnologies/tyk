package storage

import (
	"context"
	"strings"

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

	provider, err := iamauth.NewProvider(ctx, iamauth.Config{
		Provider:            strings.ToLower(strings.TrimSpace(cfg.Provider)),
		ServiceAccount:      cfg.ServiceAccount,
		RefreshBeforeExpiry: cfg.TokenRefreshBeforeExpiry,
	})
	if err != nil {
		return nil, err
	}

	return model.WithCredentialsProvider(provider), nil
}
