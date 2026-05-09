package enginev3

import (
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/tyk/apidef"
)

// FederationProvider is the Apollo Federation v2 hook layer for the engine V3
// adapter. It is implemented in `ee/middleware/graphql_federation/` and
// registered at gateway startup in EE/dev builds. CE builds register no
// provider, so federation v2 behavior is dormant — the engine V3 adapter
// behaves as a plain UDG / proxy GraphQL engine. Subgraph mode (a longstanding
// CE feature) is unaffected: its `_entities` upstream-schema wiring lives in
// the CE-visible `adapter_proxy_only.go::proxySchemaIsFederated` path.
//
// The interface is defined in the CE-visible adapter package because the
// engine adapter call sites need to compile against it without depending on
// `ee/`. The opposite direction (`ee/` importing `apidef/...`) is allowed.
type FederationProvider interface {
	// AugmentSchema returns a federation-augmented SDL when appropriate
	// (V3 ExecutionEngine: always; V3 ProxyOnly: only when the SDL has @key).
	// CE no-op returns the input unchanged.
	AugmentSchema(schemaStr string, mode apidef.GraphQLExecutionMode) (string, error)

	// BuildEntitiesDataSource produces the federation `_entities` data source
	// configuration to append to the UDG engine configuration. Returns the
	// zero DataSourceConfiguration plus a nil error when the schema is not
	// federated; callers should append only when `Factory != nil`.
	BuildEntitiesDataSource(federatedSchemaSDL string, apiDef *apidef.APIDefinition, httpClient *http.Client) (plan.DataSourceConfiguration, error)

	// ServiceSDL returns the SDL string the static `_service` data source
	// should advertise — auto-prepended @link, orphan Query fields stripped.
	// Falls back to the customer's raw SDL when not federated.
	ServiceSDL(rawSDL string, dataSources []apidef.GraphQLEngineDataSource) string
}

var registeredFederationProvider FederationProvider

// RegisterFederationProvider plugs in the EE federation implementation.
// Called from `gateway/mw_graphql_federation_ee.go::init` in EE/dev builds.
// Calling more than once replaces the prior registration — the gateway only
// registers once at startup so this is safe.
func RegisterFederationProvider(p FederationProvider) {
	registeredFederationProvider = p
}

// GetFederationProvider returns the registered provider or a no-op stub.
// The no-op stub is safe to call from any execution mode and returns inputs
// unchanged / empty data sources, which is exactly the CE behavior.
func GetFederationProvider() FederationProvider {
	if registeredFederationProvider == nil {
		return noopFederationProvider{}
	}
	return registeredFederationProvider
}

type noopFederationProvider struct{}

func (noopFederationProvider) AugmentSchema(s string, _ apidef.GraphQLExecutionMode) (string, error) {
	return s, nil
}

func (noopFederationProvider) BuildEntitiesDataSource(_ string, _ *apidef.APIDefinition, _ *http.Client) (plan.DataSourceConfiguration, error) {
	return plan.DataSourceConfiguration{}, nil
}

func (noopFederationProvider) ServiceSDL(rawSDL string, _ []apidef.GraphQLEngineDataSource) string {
	return rawSDL
}
