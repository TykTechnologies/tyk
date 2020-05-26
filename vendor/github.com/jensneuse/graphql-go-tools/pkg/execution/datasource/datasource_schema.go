package datasource

import (
	"context"
	"encoding/json"
	"io"

	"github.com/jensneuse/graphql-go-tools/pkg/introspection"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type SchemaDataSourcePlannerConfig struct {
}

type SchemaDataSourcePlannerFactoryFactory struct {
}

func (s SchemaDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &SchemaDataSourcePlannerFactory{
		base: base,
	}
	err := json.NewDecoder(configReader).Decode(&factory.config)
	if err != nil {
		return factory, err
	}
	gen := introspection.NewGenerator()
	var data introspection.Data
	var report operationreport.Report
	gen.Generate(base.Definition, &report, &data)
	factory.schemaBytes, err = json.Marshal(data)
	return factory, err
}

type SchemaDataSourcePlannerFactory struct {
	base        BasePlanner
	config      SchemaDataSourcePlannerConfig
	schemaBytes []byte
}

func (s SchemaDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return SimpleDataSourcePlanner(&SchemaDataSourcePlanner{
		BasePlanner:      s.base,
		dataSourceConfig: s.config,
		schemaBytes:      s.schemaBytes,
	})
}

type SchemaDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig SchemaDataSourcePlannerConfig
	schemaBytes      []byte
}

func (s *SchemaDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {
	return &SchemaDataSource{
		SchemaBytes: s.schemaBytes,
	}, append(s.Args, args...)
}

type SchemaDataSource struct {
	SchemaBytes []byte
}

func (s *SchemaDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {
	return out.Write(s.SchemaBytes)
}
