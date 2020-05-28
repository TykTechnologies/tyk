//go:generate packr
//go:generate graphql-go-tools gen directiveUnmarshalCode -f ./graphql_definitions/**/*.graphql -p execution -o ./datasource_config.go -s Config
package execution

import (
	"encoding/json"

	"github.com/buger/jsonparser"
	"github.com/cespare/xxhash"
	byte_template "github.com/jensneuse/byte-template"

	"github.com/jensneuse/graphql-go-tools/pkg/astnormalization"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/astvalidation"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
)

type Handler struct {
	templateDirectives []byte_template.DirectiveDefinition
	base               *datasource.BasePlanner
}

func NewHandler(base *datasource.BasePlanner, templateDirectives []byte_template.DirectiveDefinition) *Handler {
	return &Handler{
		templateDirectives: templateDirectives,
		base:               base,
	}
}

type GraphqlRequest struct {
	OperationName string          `json:"operation_name"`
	Variables     json.RawMessage `json:"variables"`
	Query         string          `json:"query"`
}

func (h *Handler) Handle(requestData, extraVariables []byte) (executor *Executor, node RootNode, ctx Context, err error) {

	var graphqlRequest GraphqlRequest
	err = json.Unmarshal(requestData, &graphqlRequest)
	if err != nil {
		return
	}

	operationDocument, report := astparser.ParseGraphqlDocumentString(graphqlRequest.Query)
	if report.HasErrors() {
		err = report
		return
	}

	variables, extraArguments := VariablesFromJson(graphqlRequest.Variables, extraVariables)

	planner := NewPlanner(h.base)
	if report.HasErrors() {
		err = report
		return
	}

	astnormalization.NormalizeOperation(&operationDocument, h.base.Definition, &report)
	if report.HasErrors() {
		err = report
		return
	}

	validator := astvalidation.DefaultOperationValidator()
	if report.HasErrors() {
		err = report
		return
	}
	validator.Validate(&operationDocument, h.base.Definition, &report)
	if report.HasErrors() {
		err = report
		return
	}
	normalizer := astnormalization.NewNormalizer(true)
	normalizer.NormalizeOperation(&operationDocument, h.base.Definition, &report)
	if report.HasErrors() {
		err = report
		return
	}
	plan := planner.Plan(&operationDocument, h.base.Definition, &report)
	if report.HasErrors() {
		err = report
		return
	}

	executor = NewExecutor(h.templateDirectives)
	ctx = Context{
		Variables:      variables,
		ExtraArguments: extraArguments,
	}

	return executor, plan, ctx, err
}

func VariablesFromJson(requestVariables, extraVariables []byte) (variables Variables, extraArguments []datasource.Argument) {
	variables = map[uint64][]byte{}
	_ = jsonparser.ObjectEach(requestVariables, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		variables[xxhash.Sum64(key)] = value
		return nil
	})
	_ = jsonparser.ObjectEach(extraVariables, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		variables[xxhash.Sum64(key)] = value
		extraArguments = append(extraArguments, &datasource.ContextVariableArgument{
			Name:         key,
			VariableName: key,
		})
		return nil
	})
	return
}
