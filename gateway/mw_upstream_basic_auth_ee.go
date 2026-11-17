//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/upstreambasicauth"
)

// upstreamAuthAvailable reports whether this build includes the upstream
// basic auth and upstream OAuth middleware (Enterprise Edition).
const upstreamAuthAvailable = true

func getUpstreamBasicAuthMw(base *BaseMiddleware) TykMiddleware {
	spec := base.Spec
	mwSpec := upstreambasicauth.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.UpstreamAuth)
	upstreamBasicAuthMw := upstreambasicauth.NewMiddleware(base.Gw, base, mwSpec)
	return WrapMiddleware(base, upstreamBasicAuthMw)
}
