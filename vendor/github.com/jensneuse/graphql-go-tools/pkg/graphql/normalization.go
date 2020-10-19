package graphql

import (
	"github.com/jensneuse/graphql-go-tools/pkg/astnormalization"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type NormalizationResult struct {
	Successful bool
	Errors     Errors
}

func (r *Request) Normalize(schema *Schema) (result NormalizationResult, err error) {
	if schema == nil {
		return NormalizationResult{Successful: false, Errors: nil}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return normalizationResultFromReport(report)
	}

	r.document.Input.Variables = r.Variables

	normalizer := astnormalization.NewNormalizer(true, true)
	normalizer.NormalizeNamedOperation(&r.document, &schema.document, []byte(r.OperationName), &report)
	if report.HasErrors() {
		return normalizationResultFromReport(report)
	}

	r.isNormalized = true

	r.Variables = r.document.Input.Variables

	return NormalizationResult{Successful: true, Errors: nil}, nil
}

func normalizationResultFromReport(report operationreport.Report) (NormalizationResult, error) {
	result := NormalizationResult{
		Successful: false,
		Errors:     nil,
	}

	if !report.HasErrors() {
		result.Successful = true
		return result, nil
	}

	result.Errors = operationValidationErrorsFromOperationReport(report)

	var err error
	if len(report.InternalErrors) > 0 {
		err = report.InternalErrors[0]
	}

	return result, err
}
