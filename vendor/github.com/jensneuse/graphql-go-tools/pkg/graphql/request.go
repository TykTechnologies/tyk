package graphql

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astnormalization"
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

func (r *Request) ValidateForSchema(schema *Schema) (result ValidationResult, err error) {
	if schema == nil {
		return ValidationResult{Valid: false, Errors: nil}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return operationValidationResultFromReport(report)
	}

	validator := astvalidation.DefaultOperationValidator()
	validator.Validate(&r.document, &schema.document, &report)
	return operationValidationResultFromReport(report)
}

func (r *Request) Normalize(schema *Schema) (result NormalizationResult, err error) {
	if schema == nil {
		return NormalizationResult{Successful: false, Errors: nil}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return normalizationResultFromReport(report)
	}

	normalizer := astnormalization.NewNormalizer(true)
	normalizer.NormalizeOperation(&r.document, &schema.document, &report)
	if report.HasErrors() {
		return normalizationResultFromReport(report)
	}

	r.isNormalized = true
	return NormalizationResult{Successful: true, Errors: nil}, nil
}

func (r *Request) CalculateComplexity(complexityCalculator ComplexityCalculator, schema *Schema) (ComplexityResult, error) {
	if schema == nil {
		return ComplexityResult{}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return complexityResult(0, 0, 0, report)
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
