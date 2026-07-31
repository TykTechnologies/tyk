//go:build ee || dev

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/TykTechnologies/tyk/certs"
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

// GetClientCertificate returns the certificate (with private key) registered
// under certID in the gateway certificate store, used to sign a private_key_jwt
// client assertion. Mirrors the upstream-certificate lookup (gateway/cert.go).
func (t *BaseMiddleware) GetClientCertificate(certID string) (*tls.Certificate, error) {
	if t.Gw == nil || t.Gw.CertificateManager == nil {
		return nil, fmt.Errorf("certificate manager unavailable")
	}
	list := t.Gw.CertificateManager.List([]string{certID}, certs.CertificatePrivate)
	if len(list) == 0 || list[0] == nil {
		return nil, fmt.Errorf("certificate %q not found or has no private key", certID)
	}
	return list[0], nil
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
