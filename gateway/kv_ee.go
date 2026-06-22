//go:build ee || dev

package gateway

import "github.com/TykTechnologies/storage/kv"

func enterpriseKVFactories() map[kv.ProviderType]kv.ProviderFactory {
	factories := make(map[kv.ProviderType]kv.ProviderFactory)

	// FIX: Uncomment after providers are implemented
	// factories[kv.AWS] = aws.NewFactory()
	// factories[kv.Azure] = azure.NewFactory()
	// factories[kv.GCP] = gcp.NewFactory()
	// factories[kv.Conjur] = conjur.NewFactory()

	return factories
}
