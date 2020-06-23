package datasource

import (
	"context"
	"encoding/json"
	"io"
)

type StaticDataSourceConfig struct {
	Data string
}

type StaticDataSourcePlannerFactoryFactory struct {
}

func (s StaticDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &StaticDataSourcePlannerFactory{
		base: base,
	}
	return factory, json.NewDecoder(configReader).Decode(&factory.config)
}

type StaticDataSourcePlannerFactory struct {
	base   BasePlanner
	config StaticDataSourceConfig
}

func (s StaticDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return SimpleDataSourcePlanner(&StaticDataSourcePlanner{
		BasePlanner:      s.base,
		dataSourceConfig: s.config,
	})
}

type StaticDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig StaticDataSourceConfig
}

func (s *StaticDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	return &StaticDataSource{
		Data: []byte(s.dataSourceConfig.Data),
	}, append(s.Args, args...)
}

type StaticDataSource struct {
	Data []byte
}

func (s StaticDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {
	return out.Write(s.Data)
}
