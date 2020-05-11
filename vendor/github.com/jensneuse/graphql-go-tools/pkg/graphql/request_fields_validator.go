package graphql

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type RequestFieldsValidator interface {
	Validate(request *Request, schema *Schema, restrictions []Type) (RequestFieldsValidationResult, error)
}

type fieldsValidator struct {
}

func (d fieldsValidator) Validate(request *Request, schema *Schema, restrictions []Type) (RequestFieldsValidationResult, error) {
	report := operationreport.Report{}
	if len(restrictions) == 0 {
		return fieldsValidationResult(report, true, "", "")
	}

	requestedTypes := make(RequestTypes)
	NewExtractor().ExtractFieldsFromRequest(request, schema, &report, requestedTypes)

	for _, restrictedType := range restrictions {
		requestedFields, hasRestrictedType := requestedTypes[restrictedType.Name]
		if !hasRestrictedType {
			continue
		}
		for _, field := range restrictedType.Fields {
			if _, hasRestrictedField := requestedFields[field]; hasRestrictedField {
				return fieldsValidationResult(report, false, restrictedType.Name, field)
			}
		}
	}

	return fieldsValidationResult(report, true, "", "")
}

type RequestFieldsValidationResult struct {
	Valid  bool
	Errors Errors
}

func fieldsValidationResult(report operationreport.Report, valid bool, typeName, fieldName string) (RequestFieldsValidationResult, error) {
	result := RequestFieldsValidationResult{
		Valid:  valid,
		Errors: nil,
	}

	var errors OperationValidationErrors
	if !result.Valid {
		errors = append(errors, OperationValidationError{
			Message: fmt.Sprintf("field: %s is restricted on type: %s", fieldName, typeName),
		})
	}
	result.Errors = errors

	if !report.HasErrors() {
		return result, nil
	}

	errors = append(errors, operationValidationErrorsFromOperationReport(report)...)
	result.Errors = errors

	var err error
	if len(report.InternalErrors) > 0 {
		err = report.InternalErrors[0]
	}

	return result, err
}
