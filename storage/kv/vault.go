package kv

import (
	"errors"
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/TykTechnologies/tyk/config"
)

// Vault is an implementation of a KV store which uses Consul as it's backend
type Vault struct {
	client *vaultapi.Client
	kvV2   bool
}

func (v *Vault) Client() *vaultapi.Client {
	return v.client
}

// NewVault returns a configured vault KV store adapter
func NewVault(conf config.VaultConfig) (Store, error) {
	return newVault(conf)
}

func (v *Vault) Get(key string) (string, error) {
	fmt.Printf("[DEBUG] Vault.Get called with key: %s\n", key)

	logicalStore := v.client.Logical()

	if v.kvV2 {
		// Version 2 engine. Make sure to append data in front
		splitKey := strings.Split(key, "/")
		if len(splitKey) > 0 {
			splitKey[0] = splitKey[0] + "/data"
			key = strings.Join(splitKey, "/")
		}
		fmt.Printf("[DEBUG] KV v2 adjusted key: %s\n", key)
	}

	splitted := strings.Split(key, ".")
	if len(splitted) != 2 {
		fmt.Printf("[DEBUG] Invalid key format. Expected 'config.value' but got: %s\n", key)
		return "", errors.New("key should be in form of config.value")
	}

	fmt.Printf("[DEBUG] Reading from Vault path: %s\n", splitted[0])
	secret, err := logicalStore.Read(splitted[0])
	if err != nil {
		fmt.Printf("[DEBUG] Vault Read error: %v\n", err)
		return "", err
	}

	if secret == nil {
		fmt.Printf("[DEBUG] No secret found at path: %s\n", splitted[0])
		return "", ErrKeyNotFound
	}

	var val map[string]interface{} = secret.Data
	fmt.Printf("[DEBUG] Raw secret data: %+v\n", val)

	if v.kvV2 {
		var ok bool
		val, ok = secret.Data["data"].(map[string]interface{})
		if !ok {
			fmt.Printf("[DEBUG] Failed to get data field from KV v2 secret\n")
			return "", ErrKeyNotFound
		}
		fmt.Printf("[DEBUG] KV v2 data field: %+v\n", val)
	}

	value, ok := val[splitted[1]]
	if !ok {
		fmt.Printf("[DEBUG] Key %s not found in secret data\n", splitted[1])
		return "", ErrKeyNotFound
	}

	fmt.Printf("[DEBUG] Found value for key %s\n", splitted[1])
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
