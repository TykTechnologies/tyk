//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/oauth2tokenexchange"
	"github.com/TykTechnologies/tyk/internal/model"
)

func getOAuth2ExchangeMw(base *BaseMiddleware) TykMiddleware {
	// OAS is required: the EE middleware reads per-operation exchange
	// overrides off Spec.OAS; nil OAS would panic on the first request.
	mwSpec := model.MergedAPI{APIDefinition: base.Spec.APIDefinition, OAS: &base.Spec.OAS}

	mw := oauth2tokenexchange.NewMiddleware(base, mwSpec)
	return WrapMiddleware(base, mw)
}
