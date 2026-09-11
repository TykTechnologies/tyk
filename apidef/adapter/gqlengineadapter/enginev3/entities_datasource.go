package enginev3

import (
	"context"
	"io"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/resolve"
)

type entitiesDataSourceFactory struct{}

func (f *entitiesDataSourceFactory) Planner(ctx context.Context) plan.DataSourcePlanner {
	return &entitiesDataSourcePlanner{}
}

type entitiesDataSourcePlanner struct{}

func (p *entitiesDataSourcePlanner) Register(visitor *plan.Visitor, configuration plan.DataSourceConfiguration, dataSourcePlannerConfiguration plan.DataSourcePlannerConfiguration) error {
	return nil
}

func (p *entitiesDataSourcePlanner) ConfigureFetch() resolve.FetchConfiguration {
	return resolve.FetchConfiguration{
		Input: `{"data":{"_entities":$$0$$}}`,
		Variables: resolve.Variables{
			&resolve.ContextVariable{
				Path: []string{"representations"},
			},
		},
		DataSource: &entitiesDataSource{},
		PostProcessing: resolve.PostProcessingConfiguration{
			SelectResponseDataPath: []string{"data", "_entities"},
		},
	}
}

func (p *entitiesDataSourcePlanner) ConfigureSubscription() plan.SubscriptionConfiguration {
	return plan.SubscriptionConfiguration{}
}

func (p *entitiesDataSourcePlanner) DataSourcePlanningBehavior() plan.DataSourcePlanningBehavior {
	return plan.DataSourcePlanningBehavior{
		MergeAliasedRootNodes:      false,
		OverrideFieldPathFromAlias: false,
	}
}

func (p *entitiesDataSourcePlanner) DownstreamResponseFieldAlias(downstreamFieldRef int) (alias string, exists bool) {
	return "", false
}

func (p *entitiesDataSourcePlanner) UpstreamSchema(dataSourceConfig plan.DataSourceConfiguration) *ast.Document {
	return nil
}

type entitiesDataSource struct{}

func (d *entitiesDataSource) Load(ctx context.Context, input []byte, w io.Writer) error {
	_, err := w.Write(input)
	return err
}

func createEntitiesDataSource() plan.DataSourceConfiguration {
	return plan.DataSourceConfiguration{
		RootNodes: []plan.TypeField{
			{
				TypeName:   "Query",
				FieldNames: []string{"_entities"},
			},
		},
		Factory: &entitiesDataSourceFactory{},
		Custom:  []byte(`{}`),
	}
}
