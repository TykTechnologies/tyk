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

	var operationValidationErrors OperationValidationErrors
	if len(report.ExternalErrors) > 0 {
		for _, externalError := range report.ExternalErrors {
			validationError := OperationValidationError{
				Message: externalError.Message,
				// TODO: add path
				// TODO: add location
			}

			operationValidationErrors = append(operationValidationErrors, validationError)
		}

		result.Errors = operationValidationErrors
	}

	var err error
	if len(report.InternalErrors) > 0 {
		err = report.InternalErrors[0]
	}

	return result, err
}
