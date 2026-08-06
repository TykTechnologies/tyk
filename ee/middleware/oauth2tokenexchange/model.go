//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// MiddlewareName is the identifier emitted in logs.
	MiddlewareName = "OAuth2TokenExchangeMiddleware"

	// DefaultIdPTimeout is the per-call timeout when the operator leaves Timeout unset.
	DefaultIdPTimeout = 15 * time.Second
)

// BaseMiddleware is the gateway.BaseMiddleware surface this package needs (avoids circular import).
type BaseMiddleware interface {
	model.LoggerProvider

	// FireEvent emits a Tyk audit event for the request.
	FireEvent(name apidef.TykEvent, meta interface{})

	// RecordExchangeMetric records one exchange decision on the OTel
	// instruments: the requests counter and the duration histogram, both
	// labelled by outcome + provider.
	RecordExchangeMetric(ctx context.Context, outcome, provider string, d time.Duration)

	// RecordExchangeCacheHit increments the dedicated cache_hit counter.
	RecordExchangeCacheHit(ctx context.Context, provider string)

	// GetClientCertificate returns the certificate (with private key) stored
	// under certID, used to sign a private_key_jwt client assertion. Errors
	// when the store is unavailable or the certificate is not found.
	GetClientCertificate(certID string) (*tls.Certificate, error)
}

// EffectiveIdPTimeout returns d, falling back to DefaultIdPTimeout when d is zero.
func EffectiveIdPTimeout(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return DefaultIdPTimeout
}
