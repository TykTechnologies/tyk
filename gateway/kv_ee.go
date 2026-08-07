//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/storage/kv/providers/aws"
	"github.com/TykTechnologies/storage/kv/providers/azure"
	"github.com/TykTechnologies/storage/kv/providers/gcp"
)

func enterpriseKVFactories() map[kv.ProviderType]kv.ProviderFactory {
	factories := make(map[kv.ProviderType]kv.ProviderFactory)

	factories[kv.AWS] = aws.NewFactory()
	factories[kv.Azure] = azure.NewFactory()
	factories[kv.GCP] = gcp.NewFactory()

	return factories
}
