package graphql

import (
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type ValidationResult struct {
	Valid  bool
	Errors Errors
}

func operationValidationResultFromReport(report operationreport.Report) (ValidationResult, error) {
	result := ValidationResult{
		Valid:  false,
		Errors: nil,
	}

	if !report.HasErrors() {
		result.Valid = true
		return result, nil
	}

	result.Errors = operationValidationErrorsFromOperationReport(report)

	var err error
	if len(report.InternalErrors) > 0 {
		err = report.InternalErrors[0]
	}

	return result, err
}
