//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/oauth2tokenexchange"
	"github.com/TykTechnologies/tyk/internal/model"
)

// EE-build factory for the TokenExchangeMiddleware. Constructs the
// real EE middleware backed by ee/middleware/oauth2tokenexchange.
//
// Story 06 wires no Redis caches and no actor token — those come in
// Stories 07 / 08. The EE factory grows in those stories.
func getOAuth2ExchangeMw(base *BaseMiddleware) TykMiddleware {
	// Both APIDefinition AND OAS are required: the EE middleware reads
	// per-operation exchange overrides off Spec.OAS via
	// GetTykMiddleware(). Passing nil OAS would nil-deref at the first
	// request.
	mwSpec := model.MergedAPI{APIDefinition: base.Spec.APIDefinition, OAS: &base.Spec.OAS}

	mw := oauth2tokenexchange.NewMiddleware(base, mwSpec)
	return WrapMiddleware(base, mw)
}
