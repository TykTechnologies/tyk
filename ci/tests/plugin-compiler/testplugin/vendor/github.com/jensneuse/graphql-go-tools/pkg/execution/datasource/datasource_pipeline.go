package datasource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"

	log "github.com/jensneuse/abstractlogger"
	"github.com/jensneuse/pipeline/pkg/pipe"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type PipelineDataSourceConfig struct {
	/*
		ConfigFilePath is the path where the Pipeline configuration file can be found
		it needs to be in the json format according to the Pipeline json schema
		see this url for more info: https://github.com/jensneuse/pipeline
	*/
	ConfigFilePath *string
	/*
			ConfigString is a string to configure the Pipeline
			it needs to be in the json format according to the Pipeline json schema
		   	see this url for more info: https://github.com/jensneuse/pipeline
			The PipelinDataSourcePlanner will always choose the configString over the configFilePath in case both are defined.
	*/
	ConfigString *string
	// InputJSON is the template to define a JSON object based on the request, parameters etc. which gets passed to the first Pipeline step
	InputJSON string
}

type PipelineDataSourcePlannerFactoryFactory struct {
}

func (p PipelineDataSourcePlannerFactoryFactory) Initialize(base BasePlanner, configReader io.Reader) (PlannerFactory, error) {
	factory := &PipelineDataSourcePlannerFactory{
		base: base,
	}
	return factory, json.NewDecoder(configReader).Decode(&factory.config)
}

type PipelineDataSourcePlannerFactory struct {
	base   BasePlanner
	config PipelineDataSourceConfig
}

func (p PipelineDataSourcePlannerFactory) DataSourcePlanner() Planner {
	return &PipelineDataSourcePlanner{
		BasePlanner:      p.base,
		dataSourceConfig: p.config,
	}
}

type PipelineDataSourcePlanner struct {
	BasePlanner
	dataSourceConfig  PipelineDataSourceConfig
	rawPipelineConfig []byte
}

func (h *PipelineDataSourcePlanner) Plan(args []Argument) (DataSource, []Argument) {

	source := PipelineDataSource{
		Log: h.Log,
	}

	err := source.Pipeline.FromConfig(bytes.NewReader(h.rawPipelineConfig))
	if err != nil {
		h.Log.Error("PipelineDataSourcePlanner.pipe.FromConfig", log.Error(err))
	}

	return &source, append(h.Args, args...)
}

func (h *PipelineDataSourcePlanner) EnterDocument(operation, definition *ast.Document) {

}

func (h *PipelineDataSourcePlanner) EnterInlineFragment(ref int) {

}

func (h *PipelineDataSourcePlanner) LeaveInlineFragment(ref int) {

}

func (h *PipelineDataSourcePlanner) EnterSelectionSet(ref int) {

}

func (h *PipelineDataSourcePlanner) LeaveSelectionSet(ref int) {

}

func (h *PipelineDataSourcePlanner) EnterField(ref int) {
	h.RootField.SetIfNotDefined(ref)
}

func (h *PipelineDataSourcePlanner) EnterArgument(ref int) {

}

func (h *PipelineDataSourcePlanner) LeaveField(ref int) {
	if !h.RootField.IsDefinedAndEquals(ref) {
		return
	}

	if h.dataSourceConfig.ConfigString != nil {
		h.rawPipelineConfig = []byte(*h.dataSourceConfig.ConfigString)
	}
	if h.dataSourceConfig.ConfigFilePath != nil {
		var err error
		h.rawPipelineConfig, err = ioutil.ReadFile(*h.dataSourceConfig.ConfigFilePath)
		if err != nil {
			h.Log.Error("PipelineDataSourcePlanner.readConfigFile", log.Error(err))
		}
	}

	h.Args = append(h.Args, &StaticVariableArgument{
		Name:  literal.INPUT_JSON,
		Value: []byte(h.dataSourceConfig.InputJSON),
	})
}

type PipelineDataSource struct {
	Log      log.Logger
	Pipeline pipe.Pipeline
}

func (r *PipelineDataSource) Resolve(ctx context.Context, args ResolverArgs, out io.Writer) (n int, err error) {

	inputJSON := args.ByKey(literal.INPUT_JSON)

	err = r.Pipeline.Run(bytes.NewReader(inputJSON), out)
	if err != nil {
		r.Log.Error("PipelineDataSource.pipe.Run", log.Error(err))
	}

	return
}
