package kv

import (
	"github.com/hashicorp/consul/api"

	"github.com/TykTechnologies/tyk/config"
)

// Consul is an implementation of a KV store which uses Consul as it's backend
type Consul struct {
	store *api.KV
}

// NewConsul returns a configured consul KV store adapter
func NewConsul(conf config.ConsulConfig) (Store, error) {
	return newConsul(conf)
}

func (c *Consul) Get(key string) (string, error) {
	pair, _, err := c.store.Get(key, nil)
	if err != nil {
		return "", err
	}

	if pair == nil {
		return "", ErrKeyNotFound
	}

	return string(pair.Value), nil
}

func newConsul(conf config.ConsulConfig) (Store, error) {
	defaultCfg := api.DefaultConfig()

	if conf.Address != "" {
		defaultCfg.Address = conf.Address
	}

	if conf.Datacenter != "" {
		defaultCfg.Datacenter = conf.Datacenter
	}

	if conf.HttpAuth.Username != "" {
		defaultCfg.HttpAuth.Username = conf.HttpAuth.Username
	}

	if conf.HttpAuth.Password != "" {
		defaultCfg.HttpAuth.Password = conf.HttpAuth.Password
	}

	if conf.WaitTime != 0 {
		defaultCfg.WaitTime = conf.WaitTime
	}

	if conf.Token != "" {
		defaultCfg.Token = conf.Token
	}

	if conf.TLSConfig.Address != "" {
		defaultCfg.TLSConfig.Address = conf.TLSConfig.Address
	}

	if conf.TLSConfig.CertFile != "" {
		defaultCfg.TLSConfig.CertFile = conf.TLSConfig.CertFile
	}

	if conf.TLSConfig.CAFile != "" {
		defaultCfg.TLSConfig.CAFile = conf.TLSConfig.CAFile
	}

	if conf.TLSConfig.InsecureSkipVerify {
		defaultCfg.TLSConfig.InsecureSkipVerify = conf.TLSConfig.InsecureSkipVerify
	}

	client, err := api.NewClient(defaultCfg)
	if err != nil {
		return nil, err
	}

	return &Consul{
		store: client.KV(),
	}, nil
}
