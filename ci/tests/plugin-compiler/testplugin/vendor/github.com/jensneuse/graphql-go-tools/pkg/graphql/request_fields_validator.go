package graphql

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type RequestFieldsValidator interface {
	Validate(request *Request, schema *Schema, restrictions []Type) (RequestFieldsValidationResult, error)
}

type FieldRestrictionValidator interface {
	ValidateByFieldList(request *Request, schema *Schema, restrictionList FieldRestrictionList) (RequestFieldsValidationResult, error)
}

type FieldRestrictionListKind int

const (
	AllowList FieldRestrictionListKind = iota
	BlockList
)

type FieldRestrictionList struct {
	Kind  FieldRestrictionListKind
	Types []Type
}

type DefaultFieldsValidator struct {
}

// Validate validates a request by checking if `restrictions` contains blocked fields.
//
// Deprecated: This function can only handle blocked fields. Use `ValidateByFieldList` if you
// want to check for blocked or allowed fields instead.
func (d DefaultFieldsValidator) Validate(request *Request, schema *Schema, restrictions []Type) (RequestFieldsValidationResult, error) {
	restrictionList := FieldRestrictionList{
		Kind:  BlockList,
		Types: restrictions,
	}

	return d.ValidateByFieldList(request, schema, restrictionList)
}

// ValidateByFieldList will validate a request by using a list of allowed or blocked fields.
func (d DefaultFieldsValidator) ValidateByFieldList(request *Request, schema *Schema, restrictionList FieldRestrictionList) (RequestFieldsValidationResult, error) {
	report := operationreport.Report{}
	if len(restrictionList.Types) == 0 {
		return fieldsValidationResult(report, true, "", "")
	}

	requestedTypes := make(RequestTypes)
	NewExtractor().ExtractFieldsFromRequest(request, schema, &report, requestedTypes)

	if restrictionList.Kind == BlockList {
		return d.checkForBlockedFields(restrictionList, requestedTypes, report)
	}

	return d.checkForAllowedFields(restrictionList, requestedTypes, report)
}

func (d DefaultFieldsValidator) checkForBlockedFields(restrictionList FieldRestrictionList, requestTypes RequestTypes, report operationreport.Report) (RequestFieldsValidationResult, error) {
	for _, typeFromList := range restrictionList.Types {
		requestedFields, hasRestrictedType := requestTypes[typeFromList.Name]
		if !hasRestrictedType {
			continue
		}
		for _, field := range typeFromList.Fields {
			_, requestHasField := requestedFields[field]
			if requestHasField {
				return fieldsValidationResult(report, false, typeFromList.Name, field)
			}
		}
	}

	return fieldsValidationResult(report, true, "", "")
}

func (d DefaultFieldsValidator) checkForAllowedFields(restrictionList FieldRestrictionList, requestTypes RequestTypes, report operationreport.Report) (RequestFieldsValidationResult, error) {
	allowedFieldsLookupMap := make(map[string]map[string]bool)
	for _, allowedType := range restrictionList.Types {
		allowedFieldsLookupMap[allowedType.Name] = make(map[string]bool)
		for _, allowedField := range allowedType.Fields {
			allowedFieldsLookupMap[allowedType.Name][allowedField] = true
		}
	}

	for requestType, requestFields := range requestTypes {
		for requestField := range requestFields {
			isAllowedField := allowedFieldsLookupMap[requestType][requestField]
			if !isAllowedField {
				return fieldsValidationResult(report, false, requestType, requestField)
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
