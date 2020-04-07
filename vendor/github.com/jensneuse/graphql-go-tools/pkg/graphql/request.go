package graphql

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/astvalidation"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

var (
	ErrEmptyRequest = errors.New("the provided request is empty")
	ErrNilSchema    = errors.New("the provided schema is nil")
)

type Request struct {
	OperationName string          `json:"operation_name"`
	Variables     json.RawMessage `json:"variables"`
	Query         string          `json:"query"`

	document ast.Document
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

func (r *Request) ValidateForSchema(schema *Schema) (result ValidationResult, err error) {
	if schema == nil {
		return ValidationResult{Valid: false, Errors: nil}, ErrNilSchema
	}

	var report operationreport.Report
	r.document, report = astparser.ParseGraphqlDocumentString(r.Query)
	if report.HasErrors() {
		return operationValidationResultFromReport(report)
	}

	validator := astvalidation.DefaultOperationValidator()
	validator.Validate(&r.document, &schema.document, &report)
	return operationValidationResultFromReport(report)
}

func (r *Request) Normalize(schema *Schema) error {
	return nil
}

func (r Request) CalculateComplexity(complexityCalculator ComplexityCalculator) int {
	return 1
}

func (r Request) Print(writer io.Writer) (n int, err error) {
	return writer.Write(nil)
}
