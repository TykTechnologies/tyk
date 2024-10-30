//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/upstreambasicauth"
)

func getUpstreamBasicAuthMw(base *BaseMiddleware) TykMiddleware {
	spec := base.Spec
	mwSpec := upstreambasicauth.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.UpstreamAuth)
	upstreamBasicAuthMw := upstreambasicauth.NewMiddleware(base.Gw, base, mwSpec)
	return WrapMiddleware(base, upstreamBasicAuthMw)
}
