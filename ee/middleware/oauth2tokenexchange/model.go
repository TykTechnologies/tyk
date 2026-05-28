//go:build ee || dev

package oauth2tokenexchange

import (
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// MiddlewareName is the identifier emitted in logs.
	MiddlewareName = "OAuth2TokenExchangeMiddleware"

	// DefaultIdPTimeout is the per-call timeout when the operator leaves Timeout unset.
	DefaultIdPTimeout = 15 * time.Second
)

// BaseMiddleware is the subset of the gateway's BaseMiddleware that
// this package needs. Defined as an interface to avoid importing gateway (circular import).
type BaseMiddleware interface {
	model.LoggerProvider
}

// EffectiveIdPTimeout returns d, falling back to DefaultIdPTimeout when d is zero.
func EffectiveIdPTimeout(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return DefaultIdPTimeout
}
