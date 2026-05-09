//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/federation"

	"github.com/TykTechnologies/tyk/apidef"
)

// augmentFederationSchema injects the Apollo Federation v2 extensions
// (`_Entity` union, `_entities`, `_service`) into the customer's SDL when the
// API is configured for federation. This is the EE-only implementation; the
// CE stub in mw_graphql_federation.go returns the SDL unchanged and warns
// when `@key` directives are present.
//
// UDG (`ExecutionEngine`) composes upstreams locally and always augments.
// Proxy-only (`ProxyOnly`) forwards `_entities` queries to an upstream
// subgraph or router, but Tyk still validates the operation against its
// known schema first; in that case we auto-detect federation by scanning for
// `@key` directives — no config flag.
func (m *GraphQLMiddleware) augmentFederationSchema(schemaStr string, executionMode apidef.GraphQLExecutionMode) (string, error) {
	switch executionMode {
	case apidef.GraphQLExecutionModeExecutionEngine:
		augmented, err := federation.BuildFederationSchema(schemaStr, schemaStr)
		if err != nil {
			return schemaStr, err
		}
		return augmented, nil
	case apidef.GraphQLExecutionModeProxyOnly:
		// Apollo Federation v2 proxy-mode passthrough: when the customer's
		// SDL declares `@key` types, Tyk forwards `_entities` queries to the
		// upstream subgraph or router. Tyk still validates the operation
		// against its known schema first, so we must inject the federation
		// extensions (`_Entity` union, `_entities`, `_service`) here.
		// Auto-detect from `@key` — no config flag.
		if !schemaHasKeyDirective(schemaStr) {
			return schemaStr, nil
		}
		augmented, err := federation.BuildFederationSchema(schemaStr, schemaStr)
		if err != nil {
			return schemaStr, err
		}
		return augmented, nil
	}
	return schemaStr, nil
}
