package kv

import (
	"errors"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/TykTechnologies/tyk/config"
)

// SecretReader allows mocking Vault in tests without a real instance.
type SecretReader interface {
	ReadSecret(path string) (*vaultapi.Secret, error)
}

// Vault is an implementation of a KV store which uses Vault as its backend
type Vault struct {
	client *vaultapi.Client
	kvV2   bool
}

func (v *Vault) Client() *vaultapi.Client {
	return v.client
}

func (v *Vault) ReadSecret(path string) (*vaultapi.Secret, error) {
	return v.client.Logical().Read(path)
}

// NewVault returns a configured vault KV store adapter
func NewVault(conf config.VaultConfig) (Store, error) {
	return newVault(conf)
}

func (v *Vault) Get(key string) (string, error) {
	logicalStore := v.client.Logical()

	if v.kvV2 {
		// Version 2 engine. Make sure to append data in front
		splitKey := strings.Split(key, "/")
		if len(splitKey) > 0 {
			splitKey[0] = splitKey[0] + "/data"
			key = strings.Join(splitKey, "/")
		}
	}

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

	var val map[string]interface{} = secret.Data

	if v.kvV2 {
		var ok bool
		val, ok = secret.Data["data"].(map[string]interface{})
		if !ok {
			// This is unlikely to happen though
			return "", ErrKeyNotFound
		}
	}

	value, ok := val[splitted[1]]
	if !ok {
		return "", ErrKeyNotFound
	}

	return value.(string), nil
}

func (v *Vault) Put(key string, value string) error {
	logicalStore := v.client.Logical()

	if v.kvV2 {
		// Version 2 engine. Make sure to append data in front
		splitKey := strings.Split(key, "/")
		if len(splitKey) > 0 {
			splitKey[0] = splitKey[0] + "/data"
			key = strings.Join(splitKey, "/")
		}
	}

	splitted := strings.Split(key, ".")
	if len(splitted) != 2 {
		return errors.New("key should be in form of config.value")
	}

	// For v2, we need to wrap the data in a data object
	var data map[string]interface{}
	if v.kvV2 {
		data = map[string]interface{}{
			"data": map[string]interface{}{
				splitted[1]: value,
			},
		}
	} else {
		data = map[string]interface{}{
			splitted[1]: value,
		}
	}

	_, err := logicalStore.Write(splitted[0], data)
	return err
}

func newVault(conf config.VaultConfig) (Store, error) {
	defaultCfg := vaultapi.DefaultConfig()

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

	client, err := vaultapi.NewClient(defaultCfg)
	if err != nil {
		return nil, err
	}

	client.SetToken(conf.Token)

	var v2 bool

	switch conf.KVVersion {

	case 1:
		v2 = false

	default:
		v2 = true
	}

	return &Vault{
		client: client,
		kvV2:   v2,
	}, nil
}
