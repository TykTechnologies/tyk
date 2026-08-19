package enginev3

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUniversalDataGraph_FederationSubgraph(t *testing.T) {
	schema := `
		type Query {
			me: User
		}
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
	`

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: schema,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{},
				DataSources:  []apidef.GraphQLEngineDataSource{},
			},
		},
	}

	udg := &UniversalDataGraph{
		ApiDefinition: apiDef,
	}

	conf, err := udg.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, conf)

	hasEntitiesDS := false
	hasServiceDS := false
	for _, ds := range conf.DataSources() {
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName == "Query" {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "_entities" {
						hasEntitiesDS = true
					}
					if fieldName == "_service" {
						hasServiceDS = true
					}
				}
			}
		}
	}

	assert.True(t, hasEntitiesDS, "Should have _entities data source")
	assert.True(t, hasServiceDS, "Should have _service data source")
}
