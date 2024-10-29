//go:build ee || dev

package gateway

import "github.com/TykTechnologies/tyk/ee/middleware/upstreamoauth"

func getUpstreamOAuthMw(base *BaseMiddleware) TykMiddleware {
	spec := base.Spec
	mwSpec := upstreamoauth.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.UpstreamAuth)
	upstreamOAuthMw := upstreamoauth.NewMiddleware(base.Gw, base, mwSpec)
	return WrapMiddleware(base, upstreamOAuthMw)
}
