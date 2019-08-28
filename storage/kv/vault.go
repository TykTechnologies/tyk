package kv

import (
	"errors"
	"strings"

	"github.com/TykTechnologies/tyk/config"
	"github.com/hashicorp/vault/api"
)

// Vault is an implementation of a KV store which uses Consul as it's backend
type Vault struct {
	client *api.Client
}

// NewVault returns a configured vault KV store adapter
func NewVault(conf config.VaultConfig) (Store, error) {
	return newVault(conf)
}

func (v *Vault) Get(key string) (string, error) {

	logicalStore := v.client.Logical()

	splitted := strings.Split(key, ".")
	if len(splitted) != 2 {
		return "", errors.New("key should be in form of config.value")
	}

	secret, err := logicalStore.Read(splitted[0])
	if err != nil {
		return "", err
	}

	if secret == nil {
		return "", ErrKeyNotFound
	}

	val, ok := secret.Data["data"]
	if !ok {
		// This is unlikely to happen though
		return "", ErrKeyNotFound
	}

	mapValues := val.(map[string]interface{})

	val, ok = mapValues[splitted[1]]
	if !ok {
		return "", ErrKeyNotFound
	}

	return val.(string), nil
}

func newVault(conf config.VaultConfig) (Store, error) {
	defaultCfg := api.DefaultConfig()

	if conf.Address != "" {
		defaultCfg.Address = conf.Address
	}

	if conf.AgentAddress != "" {
		defaultCfg.AgentAddress = conf.AgentAddress
	}

	if conf.MaxRetries > 0 {
		defaultCfg.MaxRetries = conf.MaxRetries
	}

	if conf.Timeout > 0 {
		defaultCfg.Timeout = conf.Timeout
	}

	if conf.Token == "" {
		return nil, errors.New("you must provide a root token in other to use vault")
	}

	client, err := api.NewClient(defaultCfg)
	if err != nil {
		return nil, err
	}

	client.SetToken(conf.Token)

	return &Vault{
		client: client,
	}, nil
}
