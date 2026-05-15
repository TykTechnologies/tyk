// Package graphql_federation implements the Tyk Enterprise Edition Apollo
// Federation v2 hook layer. It is plugged into the engine V3 adapter via the
// FederationProvider interface defined in
// `apidef/adapter/gqlengineadapter/enginev3/federation_provider.go` and
// registered at gateway startup from `gateway/mw_graphql_federation_ee.go`
// (build-tagged `ee || dev`).
//
// The whole directory is EE-only — covered by `ee/LICENSE-EE.md`. Files here
// carry no per-file build tags; CE builds simply never compile this package
// because nothing imports it without the `ee || dev` tag.
package graphql_federation

import (
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/tyk/apidef"
)

// Provider implements
// `apidef/adapter/gqlengineadapter/enginev3.FederationProvider`.
type Provider struct{}

// NewProvider constructs the EE federation provider. Stateless; safe to share.
func NewProvider() *Provider {
	return &Provider{}
}

// AugmentSchema injects the Apollo Federation v2 extensions into the
// customer's SDL. UDG (`ExecutionEngine`) always augments. Proxy-only
// (`ProxyOnly`) augments only when the SDL declares `@key` directives so
// non-federation proxy GraphQL APIs are unaffected.
func (Provider) AugmentSchema(schemaStr string, executionMode apidef.GraphQLExecutionMode) (string, error) {
	return augmentFederationSchema(schemaStr, executionMode)
}

// BuildEntitiesDataSource constructs the federation `_entities` data source.
// The factory is wired with per-entity REST / GraphQL resolvers derived from
// the customer's data sources. Returns the zero value plus a nil error when
// the schema is not federated; callers should append only when
// `Factory != nil`.
func (Provider) BuildEntitiesDataSource(federatedSchemaSDL string, apiDef *apidef.APIDefinition, httpClient *http.Client) (plan.DataSourceConfiguration, error) {
	resolvers, err := buildEntityResolvers(apiDef.GraphQL.Schema, apiDef.GraphQL.Engine.DataSources, httpClient)
	if err != nil {
		return plan.DataSourceConfiguration{}, err
	}
	return createEntitiesDataSource(federatedSchemaSDL, resolvers)
}

// ServiceSDL returns the SDL string the static `_service` data source should
// advertise. Federation-shaped schemas get an auto-prepended v2 `@link` (when
// no explicit federation `@link` is present) and orphan Query fields stripped;
// plain GraphQL schemas pass through unchanged.
func (Provider) ServiceSDL(rawSDL string, dataSources []apidef.GraphQLEngineDataSource) string {
	return serviceSDL(rawSDL, dataSources)
}
