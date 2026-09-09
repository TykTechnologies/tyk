//go:build !ee && !dev

package gateway

import (
	"net/http"
	"sync"
)

// getOAuth2ExchangeMw returns a noop shim on OSS builds (mirrors mw_oauth2_auth.go / mw_streaming.go).
func getOAuth2ExchangeMw(base *BaseMiddleware) TykMiddleware {
	return &noopOAuth2Exchange{BaseMiddleware: base}
}

type noopOAuth2Exchange struct {
	*BaseMiddleware
	logOnce sync.Once
}

//nolint:staticcheck // ST1008: TykMiddleware.ProcessRequest interface requires (error, int) return order.
func (d *noopOAuth2Exchange) ProcessRequest(_ http.ResponseWriter, _ *http.Request, _ interface{}) (error, int) {
	return nil, http.StatusOK
}

// EnabledForSpec always returns false but logs once when tokenExchange.enabled=true on an OSS build.
func (d *noopOAuth2Exchange) EnabledForSpec() bool {
	if d.Spec == nil || !d.Spec.IsOAS {
		return false
	}
	if _, cfg := d.Spec.GetOAuth2Config(); cfg != nil && cfg.TokenExchange != nil && cfg.TokenExchange.Enabled {
		d.logOnce.Do(func() {
			d.Logger().Error("OAuth2 token exchange is supported only in Tyk Enterprise Edition; the configured tokenExchange block is being ignored on this build")
		})
	}
	return false
}

func (d *noopOAuth2Exchange) Name() string {
	return "NoopOAuth2Exchange"
}
