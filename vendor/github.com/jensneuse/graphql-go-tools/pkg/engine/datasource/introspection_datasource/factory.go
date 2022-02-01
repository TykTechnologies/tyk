package introspection_datasource

import (
	"context"

	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/introspection"
)

type Factory struct {
	introspectionData *introspection.Data
}

func NewFactory(introspectionData *introspection.Data) *Factory {
	return &Factory{introspectionData: introspectionData}
}

func (f *Factory) Planner(_ context.Context) plan.DataSourcePlanner {
	return &Planner{introspectionData: f.introspectionData}
}
