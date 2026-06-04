//go:build ee || dev

package gateway

import (
	"context"
	"time"

	"github.com/TykTechnologies/tyk/ee/middleware/oauth2tokenexchange"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	"github.com/TykTechnologies/tyk/storage"
)

// RecordExchangeMetric records one token-exchange decision on the gateway's
// OTel instruments. Safe to call when metrics are not initialised.
func (t *BaseMiddleware) RecordExchangeMetric(ctx context.Context, outcome, provider string, d time.Duration) {
	if t.Gw == nil || t.Gw.MetricInstruments == nil {
		return
	}
	t.Gw.MetricInstruments.RecordExchange(ctx, outcome, provider, d)
}

// RecordExchangeCacheHit increments the gateway's token-exchange cache_hit
// counter. Safe to call when metrics are not initialised.
func (t *BaseMiddleware) RecordExchangeCacheHit(ctx context.Context, provider string) {
	if t.Gw == nil || t.Gw.MetricInstruments == nil {
		return
	}
	t.Gw.MetricInstruments.RecordCacheHit(ctx, provider)
}

// RecordActorAcquisition records one client-credentials actor-token acquisition
// on the gateway's OTel instruments. Safe to call when metrics are not initialised.
func (t *BaseMiddleware) RecordActorAcquisition(ctx context.Context, outcome, provider string, d time.Duration) {
	if t.Gw == nil || t.Gw.MetricInstruments == nil {
		return
	}
	t.Gw.MetricInstruments.RecordActorAcquisition(ctx, outcome, provider, d)
}

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
