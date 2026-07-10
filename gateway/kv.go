// This file is the gateway's KV resolution surface: registry lifecycle
// (ensureKVRegistry/closeKVRegistry), the legacy-scheme resolution shim
// (kvStore/kvStoreCtx) with its hot-reload closure registration (resolveKV),
// and the legacy vault/consul store setup that bulk operations at API Definition
// still depend on (setUpVault/setUpConsul).

package gateway

import (
	"context"
	"errors"
	"strings"

	kvLib "github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/resolver"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage/kv"
)

func (gw *Gateway) resolveKV(original string, set func(*config.Config, string), hotReload bool) (string, error) {
	resolved, err := gw.kvStore(original)
	if err != nil {
		return original, err
	}
	if hotReload && resolved != original {
		gw.kvResolvers = append(gw.kvResolvers, func() error {
			val, err := gw.kvStoreCtx(kvLib.WithCacheBypass(gw.ctx), original)
			if err != nil {
				return err
			}
			conf := gw.GetConfig()
			set(&conf, val)
			gw.SetConfig(conf)
			return nil
		})
	}
	return resolved, nil
}

// kvStore resolves a single KV reference using the gateway's base context.
func (gw *Gateway) kvStore(value string) (string, error) {
	return gw.kvStoreCtx(gw.ctx, value)
}

// kvStoreCtx is kvStore with an explicit context, so a caller can carry a
// directive through to the store.
func (gw *Gateway) kvStoreCtx(ctx context.Context, value string) (string, error) {

	if strings.HasPrefix(value, "secrets://") {
		key := strings.TrimPrefix(value, "secrets://")
		log.Debugf("Retrieving %s from secret store in config", key)

		store, err := gw.kvRegistry.GetStore("secrets")
		if err != nil {
			return "", err
		}

		val, err := store.Get(ctx, key)
		if err != nil {
			return "", err
		}

		return val, nil
	}

	if strings.HasPrefix(value, "env://") {
		key := strings.TrimPrefix(value, "env://")
		log.Debugf("Retrieving %s from environment", key)

		store, err := gw.kvRegistry.GetStore("env")
		if err != nil {
			log.WithError(err).Error("Failed to retrieve env store")

			return "", nil
		}

		return store.Get(ctx, key)
	}

	if strings.HasPrefix(value, "consul://") {
		key := strings.TrimPrefix(value, "consul://")
		log.Debugf("Retrieving %s from consul", key)
		store, err := gw.kvRegistry.GetStore("consul")
		if err != nil {
			log.Error(`Failed to get store: `, err)

			return value, nil
		}

		return store.Get(ctx, key)
	}

	if strings.HasPrefix(value, "vault://") {
		key := strings.TrimPrefix(value, "vault://")
		log.Debugf("Retrieving %s from vault", key)

		resolved, err := gw.kvResolver.Resolve(ctx, "kv://vault/"+vaultDotToFragment(key))
		if errors.Is(err, kvLib.ErrStoreNotFound) {
			log.Error(`Failed to get store: `, err)

			return value, nil
		}

		return resolved, err
	}

	if strings.HasPrefix(value, "file://") {
		key := strings.TrimPrefix(value, "file://")
		log.Debugf("Retrieving %s from kv file", key)

		store, err := gw.kvRegistry.GetStore("file")
		if err != nil {
			return "", err

		}

		return store.Get(ctx, key)
	}

	return gw.kvResolver.Resolve(ctx, value)
}

func (gw *Gateway) setUpVault() error {
	if gw.vaultKVStore != nil {
		return nil
	}

	var err error

	gw.vaultKVStore, err = kv.NewVault(gw.GetConfig().KV.Vault)
	if err != nil {
		log.Debugf("an error occurred while setting up vault... %v", err)
	}

	return err
}

func (gw *Gateway) setUpConsul() error {
	if gw.consulKVStore != nil {
		return nil
	}

	var err error

	gw.consulKVStore, err = kv.NewConsul(gw.GetConfig().KV.Consul)
	if err != nil {
		log.Debugf("an error occurred while setting up consul.. %v", err)
	}

	return err
}

func (gw *Gateway) ensureKVRegistry(conf config.Config) error {
	// Constructing a gateway with a nil context is a long-supported test
	// convenience; the registry bootstrap derives contexts internally and
	// panics on a nil parent, so normalize here.
	ctx := gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	if gw.kvRegistry == nil {
		reg, err := config.NewLocalKVRegistry(ctx, &conf)
		if err != nil {
			return err
		}

		gw.kvRegistry = reg
	}

	if gw.kvResolver == nil {
		gw.kvResolver = resolver.NewResolver(gw.kvRegistry)
	}

	return nil
}

func (gw *Gateway) closeKVRegistry(ctx context.Context) {
	if gw.kvRegistry == nil {
		return
	}

	if err := gw.kvRegistry.Close(ctx); err != nil {
		mainLog.WithError(err).Error("Error closing KV registry")
	}
}
