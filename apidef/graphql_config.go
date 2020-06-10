package apidef

import (
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
)

const (
	// GraphQLExecutionModeProxyOnly is the mode in which the GraphQL Middleware doesn't evaluate the GraphQL request
	// In other terms, the GraphQL Middleware will not act as a GraphQL server in itself.
	// The GraphQL Middleware will (optionally) validate the request and leave the execution up to the upstream.
	GraphQLExecutionModeProxyOnly GraphQLExecutionMode = "proxyOnly"
	// GraphQLExecutionModeExecutionEngine is the mode in which the GraphQL Middleware will evaluate every request.
	// This means the Middleware will act as a independent GraphQL service which might delegate partial execution to upstreams.
	GraphQLExecutionModeExecutionEngine GraphQLExecutionMode = "executionEngine"
)

// GraphQLConfig is the root config object for a GraphQL API.
type GraphQLConfig struct {
	// Enabled indicates if GraphQL should be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`
	// ExecutionMode is the mode to define how an api behaves.
	ExecutionMode GraphQLExecutionMode `bson:"execution_mode" json:"execution_mode"`
	// Schema is the GraphQL Schema exposed by the GraphQL API/Upstream/Engine.
	Schema string `bson:"schema" json:"schema"`
	// TypeFieldConfigurations is a rule set of data source and mapping of a schema field.
	TypeFieldConfigurations []datasource.TypeFieldConfiguration `bson:"type_field_configurations" json:"type_field_configurations"`
	// GraphQLPlayground is the Playground specific configuration.
	GraphQLPlayground GraphQLPlayground `bson:"playground" json:"playground"`
}

// GraphQLExecutionMode is the mode in which the GraphQL Middleware should operate.
type GraphQLExecutionMode string

// GraphQLPlayground represents the configuration for the public playground which will be hosted alongside the api.
type GraphQLPlayground struct {
	// Enabled indicates if the playground should be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Path sets the path on which the playground will be hosted if enabled.
	Path string `bson:"path" json:"path"`
}

// ValidateSchema - validates that graphql schema is correct
func (g GraphQLConfig) ValidateSchema() (err error) {
	_, report := astparser.ParseGraphqlDocumentString(g.Schema)
	if report.HasErrors() {
		return report
	}

	return nil
}

func (g GraphQLConfig) ValidateTypeFieldConfigurations() (err error) {
	// TODO: do validation

	return nil
}
