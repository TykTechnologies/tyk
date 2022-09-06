package datasource

import (
	"context"
	"encoding/json"
	"io"
)

type TypeDataSourcePlannerConfig struct {
}

type TypeDataSourcePlannerFactoryFactory struct {
}

func (t TypeDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := TypeDataSourcePlannerFactory{
		base: base,
	}
	return factory, json.NewDecoder(configReader).Decode(&factory.config)
}

type TypeDataSourcePlannerFactory struct {
	base   BasePlanner
	config TypeDataSourcePlannerConfig
}

func (t TypeDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return SimpleDataSourcePlanner(&TypeDataSourcePlanner{
		BasePlanner:      t.base,
		dataSourceConfig: t.config,
	})
}

type TypeDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig TypeDataSourcePlannerConfig
}

func (t *TypeDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	return &TypeDataSource{}, append(t.Args, args...)
}

type TypeDataSource struct {
}

func (t *TypeDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {
	return
}
