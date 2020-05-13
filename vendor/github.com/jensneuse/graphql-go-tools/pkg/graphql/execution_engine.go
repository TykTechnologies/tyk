package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/jensneuse/abstractlogger"

	"github.com/jensneuse/graphql-go-tools/pkg/execution"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type DataSourceHttpJsonOptions struct {
	HttpClient *http.Client
}

type DataSourceGraphqlOptions struct {
	HttpClient *http.Client
}

type ExecutionOptions struct {
	ExtraArguments json.RawMessage
}

type ExecutionEngine struct {
	logger      abstractlogger.Logger
	basePlanner *datasource.BasePlanner
	executor    *execution.Executor
	schema      *Schema
}

func NewExecutionEngine(logger abstractlogger.Logger, schema *Schema, plannerConfig datasource.PlannerConfiguration) (*ExecutionEngine, error) {
	executor := execution.NewExecutor(nil)
	basePlanner, err := datasource.NewBaseDataSourcePlanner(schema.rawInput, plannerConfig, logger)
	if err != nil {
		return nil, err
	}

	return &ExecutionEngine{
		logger:      logger,
		basePlanner: basePlanner,
		executor:    executor,
		schema:      schema,
	}, nil
}

func (e *ExecutionEngine) AddHttpJsonDataSource(name string) error {
	return e.AddHttpJsonDataSourceWithOptions(name, DataSourceHttpJsonOptions{})
}

func (e *ExecutionEngine) AddHttpJsonDataSourceWithOptions(name string, options DataSourceHttpJsonOptions) error {
	httpJsonFactoryFactory := &datasource.HttpJsonDataSourcePlannerFactoryFactory{}

	if options.HttpClient != nil {
		httpJsonFactoryFactory.Client = options.HttpClient
	}

	return e.AddDataSource(name, httpJsonFactoryFactory)
}

func (e *ExecutionEngine) AddGraphqlDataSource(name string) error {
	return e.AddGraphqlDataSourceWithOptions(name, DataSourceGraphqlOptions{})
}

func (e *ExecutionEngine) AddGraphqlDataSourceWithOptions(name string, options DataSourceGraphqlOptions) error {
	graphqlFactoryFactory := &datasource.GraphQLDataSourcePlannerFactoryFactory{}

	if options.HttpClient != nil {
		graphqlFactoryFactory.Client = options.HttpClient
	}

	return e.AddDataSource(name, graphqlFactoryFactory)
}

func (e *ExecutionEngine) AddDataSource(name string, plannerFactoryFactory datasource.PlannerFactoryFactory) error {
	return e.basePlanner.RegisterDataSourcePlannerFactory(name, plannerFactoryFactory)
}

func (e *ExecutionEngine) ExecuteWithWriter(ctx context.Context, operation *Request, writer io.Writer, options ExecutionOptions) error {
	var report operationreport.Report
	if !operation.IsNormalized() {
		normalizationResult, err := operation.Normalize(e.schema)
		if err != nil {
			return err
		}

		if !normalizationResult.Successful {
			return normalizationResult.Errors
		}
	}

	planner := execution.NewPlanner(e.basePlanner)
	plan := planner.Plan(&operation.document, e.basePlanner.Definition, &report)
	if report.HasErrors() {
		return report
	}

	variables, extraArguments := execution.VariablesFromJson(operation.Variables, options.ExtraArguments)
	executionContext := execution.Context{
		Context:        ctx,
		Variables:      variables,
		ExtraArguments: extraArguments,
	}

	return e.executor.Execute(executionContext, plan, writer)
}

func (e *ExecutionEngine) Execute(ctx context.Context, operation *Request, options ExecutionOptions) (*ExecutionResult, error) {
	var buf bytes.Buffer
	err := e.ExecuteWithWriter(ctx, operation, &buf, options)
	return &ExecutionResult{&buf}, err
}

type ExecutionResult struct {
	buf *bytes.Buffer
}

func (r *ExecutionResult) Buffer() *bytes.Buffer {
	return r.buf
}

func (r *ExecutionResult) GetAsHTTPResponse() (res *http.Response) {
	if r.buf == nil {
		return
	}

	res = &http.Response{}
	res.Body = ioutil.NopCloser(r.buf)
	res.Header = make(http.Header)
	res.StatusCode = 200

	res.Header.Set("Content-Type", "application/json")

	return
}
