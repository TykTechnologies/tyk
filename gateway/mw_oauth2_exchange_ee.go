//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/oauth2tokenexchange"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	"github.com/TykTechnologies/tyk/storage"
)

func getOAuth2ExchangeMw(base *BaseMiddleware) TykMiddleware {
	// OAS is required: the EE middleware reads per-operation exchange
	// overrides off Spec.OAS; nil OAS would panic on the first request.
	mwSpec := model.MergedAPI{APIDefinition: base.Spec.APIDefinition, OAS: &base.Spec.OAS}

	var cache oauth2common.ExchangeCache
	if _, cfg := base.Spec.GetOAuth2Config(); cfg != nil && cfg.TokenExchange != nil && cfg.TokenExchange.Enabled {
		for _, p := range cfg.TokenExchange.Providers {
			if p.Cache != nil && p.Cache.Enabled {
				// The cache key already carries the oauth2:exchange: namespace; the
				// store uses raw-key ops, so no KeyPrefix/HashKeys is applied here.
				store := &storage.RedisCluster{
					ConnectionHandler: base.Gw.StorageConnectionHandler,
				}
				store.Connect()
				cache = newRedisExchangeCache(store, base.Gw.GetConfig().Secret)
				break
			}
		}
	}

	mw := oauth2tokenexchange.NewMiddleware(base, mwSpec, cache)
	return WrapMiddleware(base, mw)
}
