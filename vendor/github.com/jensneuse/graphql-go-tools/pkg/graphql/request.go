package graphql

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/middleware/operation_complexity"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

const (
	defaultInrospectionQueryName = "IntrospectionQuery"
	schemaFieldName              = "__schema"
)

var (
	ErrEmptyRequest = errors.New("the provided request is empty")
	ErrNilSchema    = errors.New("the provided schema is nil")
	ErrEmptySchema  = errors.New("the provided schema is empty")
)

type Request struct {
	OperationName string          `json:"operationName"`
	Variables     json.RawMessage `json:"variables"`
	Query         string          `json:"query"`

	document     ast.Document
	isParsed     bool
	isNormalized bool
}

func UnmarshalRequest(reader io.Reader, request *Request) error {
	requestBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}

	if len(requestBytes) == 0 {
		return ErrEmptyRequest
	}

	return json.Unmarshal(requestBytes, &request)
}

func (r *Request) CalculateComplexity(complexityCalculator ComplexityCalculator, schema *Schema) (ComplexityResult, error) {
	if schema == nil {
		return ComplexityResult{}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return complexityResult(
			operation_complexity.OperationStats{},
			[]operation_complexity.RootFieldStats{},
			report,
		)
	}

	return complexityCalculator.Calculate(&r.document, &schema.document)
}

func (r Request) Print(writer io.Writer) (n int, err error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return 0, report
	}

	return writer.Write(r.document.Input.RawBytes)
}

func (r *Request) IsNormalized() bool {
	return r.isNormalized
}

func (r *Request) parseQueryOnce() (report operationreport.Report) {
	if r.isParsed {
		return report
	}

	r.isParsed = true
	r.document, report = astparser.ParseGraphqlDocumentString(r.Query)
	return report
}

func (r *Request) IsIntrospectionQuery() (result bool, err error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return false, report
	}

	if r.OperationName == defaultInrospectionQueryName {
		return true, nil
	}

	if len(r.document.RootNodes) == 0 {
		return
	}

	rootNode := r.document.RootNodes[0]
	if rootNode.Kind != ast.NodeKindOperationDefinition {
		return
	}

	operationDef := r.document.OperationDefinitions[rootNode.Ref]
	if operationDef.OperationType != ast.OperationTypeQuery {
		return
	}
	if !operationDef.HasSelections {
		return
	}

	selectionSet := r.document.SelectionSets[operationDef.SelectionSet]
	if len(selectionSet.SelectionRefs) == 0 {
		return
	}

	selection := r.document.Selections[selectionSet.SelectionRefs[0]]
	if selection.Kind != ast.SelectionKindField {
		return
	}

	return r.document.FieldNameString(selection.Ref) == schemaFieldName, nil
}
