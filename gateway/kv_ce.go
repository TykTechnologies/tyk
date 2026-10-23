//go:build !ee && !dev

package gateway

import "github.com/TykTechnologies/storage/kv"

func enterpriseKVFactories() map[kv.ProviderType]kv.ProviderFactory {
	return nil
}
