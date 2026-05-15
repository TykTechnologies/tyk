//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter/enginev3"
	graphql_federation "github.com/TykTechnologies/tyk/ee/middleware/graphql_federation"
)

// init registers the EE Apollo Federation v2 provider with the engine V3
// adapter. The CE build of `mw_graphql_federation.go` registers nothing, so
// the adapter falls back to its no-op provider — federation behavior is
// dormant in CE binaries. Mirrors the dispatcher pattern used by streams,
// upstreambasicauth, and upstreamoauth: the actual implementation lives
// under `ee/middleware/graphql_federation/` (covered by `ee/LICENSE-EE.md`)
// and the gateway plugs it in here.
func init() {
	enginev3.RegisterFederationProvider(graphql_federation.NewProvider())
}

// augmentFederationSchema injects the Apollo Federation v2 extensions
// (`_Entity` union, `_entities`, `_service`) into the customer's SDL. The
// real logic lives in `ee/middleware/graphql_federation`; this gateway hook
// just reaches the registered provider so the call site in `mw_graphql.go`
// is build-tag agnostic.
func (m *GraphQLMiddleware) augmentFederationSchema(schemaStr string, executionMode apidef.GraphQLExecutionMode) (string, error) {
	return enginev3.GetFederationProvider().AugmentSchema(schemaStr, executionMode)
}
