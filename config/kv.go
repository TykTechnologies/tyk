// This file is the storage/kv integration seam: legacy config-block promotion
// (buildKVConfig), the load + registry bootstrap path (LoadAndInitKVRegistry),
// and the local-only registry for callers that bypass it (NewLocalKVRegistry).

package config

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/registry"
	"github.com/sirupsen/logrus"
)

type kvLogger struct{ l *logrus.Logger }

func (a kvLogger) Warn(msg string, fields map[string]any) { a.l.WithFields(fields).Warn(msg) }
func (a kvLogger) Warnf(format string, args ...any)       { a.l.Warnf(format, args...) }

// NewLocalKVRegistry builds a registry containing ONLY the local stores
// (env, file, secrets) promoted from conf — no network, no kv.stores parsing,
// no resolution. It is the registry a caller uses when it has an in-memory
// config but must not go through LoadAndInitKVRegistry (the gateway's test-mode
// construction path).
func NewLocalKVRegistry(ctx context.Context, conf *Config) (*registry.Registry, error) {
	all := buildKVConfig(conf)

	local := make(map[string]kv.StoreConfig, len(all))
	for name, sc := range all {
		if sc.Type.IsLocal() {
			local[name] = sc
		}
	}

	return registry.NewFromConfig(
		ctx,
		nil,
		registry.WithDefaultStores(local),
		registry.WithInitLogger(kvLogger{l: log}),
	)
}

// LoadAndInitKVRegistry runs Load, then builds the KV registry from the config's
// store blocks. It does NOT resolve references in the config — individual fields
// (secrets, certificates) are resolved later at their point of consumption
// (afterConfSetup / per-API). The caller owns the returned registry and its Close.
func LoadAndInitKVRegistry(
	ctx context.Context,
	paths []string,
	conf *Config,
	factories map[kv.ProviderType]kv.ProviderFactory,
) (*registry.Registry, error) {
	err := Load(paths, conf)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	marshaledBytes, err := json.Marshal(conf)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}

	r, err := registry.NewFromConfig(
		ctx,
		marshaledBytes,
		registry.WithDefaultStores(buildKVConfig(conf)),
		registry.WithFactories(factories),
		registry.WithInitLogger(kvLogger{l: log}),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize KV registry: %w", err)
	}

	return r, nil
}

// buildKVConfig translates the legacy tyk.conf KV blocks (vault, consul, file,
// secrets) into the store map the storage/kv library understands.
func buildKVConfig(cfg *Config) map[string]kv.StoreConfig {
	stores := make(map[string]kv.StoreConfig)

	// prefix+uppercase reproduces the legacy os.Getenv("TYK_SECRET_" + ToUpper(key)).
	// Every json.Marshal here takes static scalars and cannot fail — err is discarded.
	envCfg, _ := json.Marshal(map[string]any{
		"prefix":    "TYK_SECRET_",
		"uppercase": true,
	})
	stores["env"] = kv.StoreConfig{
		Type:   kv.Env,
		Config: envCfg,
	}

	fileCfg, _ := json.Marshal(cfg.KV.File)
	stores["file"] = kv.StoreConfig{
		Type:   kv.File,
		Config: fileCfg,
	}

	// Names "secrets" so legacy secrets:// references route here; values are literal.
	if len(cfg.Secrets) > 0 {
		data, _ := json.Marshal(map[string]any{
			"data": cfg.Secrets,
		})

		stores["secrets"] = kv.StoreConfig{
			Type:   kv.Inline,
			Config: data,
		}
	}

	// vault and consul stay Required:false — legacy warn-and-continue: an unreachable
	// backend at startup logs a warning, it must not abort the gateway.
	if cfg.KV.Vault.Address != "" || cfg.KV.Vault.Token != "" {
		stores["vault"] = kv.StoreConfig{Type: kv.Vault, Config: marshalVaultConfig(cfg.KV.Vault)}
	}

	if cfg.KV.Consul.Address != "" {
		stores["consul"] = kv.StoreConfig{Type: kv.Consul, Config: marshalConsulConfig(cfg.KV.Consul)}
	}

	return stores

}

// marshalVaultConfig serializes VaultConfig, converting Timeout (a time.Duration,
// which marshals as int64 ns) to the "5s" string the vault provider expects.
func marshalVaultConfig(v VaultConfig) json.RawMessage {
	cfg := struct {
		Address      string `json:"address"`
		AgentAddress string `json:"agent_address"`
		Token        string `json:"token"`
		MaxRetries   int    `json:"max_retries"`
		Timeout      string `json:"timeout"`
		KVVersion    int    `json:"kv_version"`
	}{
		Address:      v.Address,
		AgentAddress: v.AgentAddress,
		Token:        v.Token,
		MaxRetries:   v.MaxRetries,
		Timeout:      v.Timeout.String(),
		KVVersion:    v.KVVersion,
	}
	b, _ := json.Marshal(cfg)

	return b
}

// marshalConsulConfig serializes ConsulConfig, converting WaitTime (a time.Duration,
// which marshals as int64 ns) to the "5s" string the consul provider expects.
func marshalConsulConfig(c ConsulConfig) json.RawMessage {
	type alias ConsulConfig

	b, _ := json.Marshal(struct {
		alias
		WaitTime string `json:"wait_time"`
	}{
		alias:    alias(c),
		WaitTime: c.WaitTime.String(),
	})

	return b
}
